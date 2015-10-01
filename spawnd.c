#define _BSD_SOURCE
#define _XOPEN_SOURCE 600
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <syslog.h>
#include <mqueue.h>
#include "misc.h"
#include "config.h"
#include "ipc.h"

struct service {
	int pipe[2];
	char *name;
	char **depends;
	unsigned long long int spawn_time, spawn_term_time, script_time;
	unsigned int script_timeout, script_kill_timeout;
	enum service_status status, target_status;
	pid_t spawn_pid, script_pid;
	short int after_all;
};

struct services_list {
	struct service **i;
	size_t n;
	size_t s;
};

char current_domain[DOMAIN_NAME_MAX_LEN];

pid_t self_pid;
int respawn_interval;
int script_timeout;
int script_kill_timeout;
unsigned long long int alarm_time;
unsigned long long int cur_time;
const char *term_domain;
const char *reopen_device;
const char *start_domain;
int verbose_level;
int debug;
int reexec_lock;
int dummy_pipe[2];
int setup_domain_progress;
int setup_domain;
int dont_reap_childs;
int ctl_socket;
mqd_t mq;

char *memory_log;
size_t memory_log_length, memory_log_size;
enum log_type log_type;

struct sigaction old_term_act;
struct sigaction old_int_act;
struct sigaction old_hup_act;
struct sigaction old_chld_act;
struct sigaction old_alrm_act;
struct sigaction old_pipe_act;
struct sigaction old_usr1_act;

sigset_t block_signals;

void message(int level, const char *fmt, ...);
void services_process();
void fd_to_message(int fd, const char * title);

struct services_list services;

int fd_is_read_ready(int fd, int timeout) {
	if (fd < 0) return 0;
	int retval;

	struct pollfd fds;
	fds.fd = fd;
	fds.events = POLLIN;
	retval = poll(&fds, 1, timeout);
	if (retval > 0) {
		return 1;
	};
	return 0;
};

void memory_log_to_log() {
	if (!memory_log_length) {
		return;
	};
	size_t log_pos = 0;
	while (log_pos < memory_log_length) {
		message(0, "%s", &memory_log[log_pos]);
		log_pos += strlen(&memory_log[log_pos]) + 1;
	};
	free(memory_log);
	memory_log = NULL;
	memory_log_length = 0;
};

void child_handler() {
	int status;
	pid_t child_pid;
	size_t i;
	for (i = 0; i < services.n; i++) {
		if (services.i[i]->spawn_pid > 0 && waitpid(services.i[i]->spawn_pid, &status, WNOHANG) > 0) {
			if (services.i[i]->target_status == SERVICE_ON) {
				message(0, "service %s is failed\n", services.i[i]->name);
				services.i[i]->status = SERVICE_FAILED;
			};
			services.i[i]->spawn_pid = -1;
		};
		if (services.i[i]->script_pid > 0 && waitpid(services.i[i]->script_pid, &status, WNOHANG) > 0) {
			message(1, "Script for service %s finished.\n", services.i[i]->name);
			if (status) {
				message(0, "Warning: Script for service %s return not success status.\n", services.i[i]->name);
			};
			services.i[i]->script_pid = -1;
			break;
		};
	};
	services_process();
	if (!dont_reap_childs) {
		while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
			message(3, "PID %li change status\n", (long int)child_pid);
			if ((WIFEXITED(status) || WIFSIGNALED(status)) && child_pid > 0) {
				message(3, "PID %li is dead\n", (long int)child_pid);
				for (i = 0; i < services.n; i++) {
					if (services.i[i]->spawn_pid == child_pid) {
						if (services.i[i]->target_status == SERVICE_ON) {
							message(0, "service %s is failed\n", services.i[i]->name);
							services.i[i]->status = SERVICE_FAILED;
						};
						services.i[i]->spawn_pid = -1;
						break;
					} else if (services.i[i]->script_pid == child_pid) {
						services.i[i]->script_pid = -1;
						break;
					};
				};
			};
		};
	};
	return;
};

time_t monothonic_time() {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec;
};

void progress_bar() {
	size_t all = services.n, count = 0, failed = 0;
	size_t i;
	for (i = 0; i < all; i++) {
		if (services.i[i]->target_status == services.i[i]->status) {
			count++;
		} else if (services.i[i]->status == SERVICE_FAILED) {
			failed++;
		};
	};
	FILE *out = fopen(reopen_device, "w+");
	if (!out) return;
	if (!all) {
		fprintf(out, "\nDomain %s: no tasks.\n", current_domain);
	} else {
		fprintf(out, "\nDomain %s: %zi/%zi (%i%%) tasks completed. %zi (%i%%) failed. %zi (%i%%) success\n", current_domain, count, all, (int)(100 * (count + failed) / all), failed,  (int)(100 * failed / all), count,  (int)(100 * count / all));
	};
	fclose(out);
};

void close_all_pipes() {
	int i;
	for (i=0; i < services.n; i++) {
		close(services.i[i]->pipe[0]);
		close(services.i[i]->pipe[1]);
	};
	close(dummy_pipe[0]);
	close(dummy_pipe[1]);
};

void restore_signals() {
	sigprocmask(SIG_UNBLOCK, &block_signals, NULL);
	sigaction(SIGCHLD, &old_chld_act, NULL);
	sigaction(SIGUSR1, &old_usr1_act, NULL);
	sigaction(SIGALRM, &old_alrm_act, NULL);
	sigaction(SIGTERM, &old_term_act, NULL);
	sigaction(SIGINT, &old_int_act, NULL);
	sigaction(SIGHUP, &old_hup_act, NULL);
	sigaction(SIGPIPE, &old_pipe_act, NULL);
};

void reexec() {
	char verbose_level_str[8];
	verbose_level_str[0]='\0';
	snprintf(verbose_level_str, 8, "%i", verbose_level);
	char respawn_interval_str[8];
	respawn_interval_str[0]='\0';
	snprintf(respawn_interval_str, 8, "%i", respawn_interval);
	char script_timeout_str[8];
	script_timeout_str[0]='\0';
	snprintf(script_timeout_str, 8, "%i", script_timeout);
	char script_kill_timeout_str[8];
	script_kill_timeout_str[0]='\0';
	snprintf(script_kill_timeout_str, 8, "%i", script_kill_timeout);
	close_all_pipes();
	reexec_lock = 1;
	restore_signals();
	mq_close(mq);
	execl(
			SPAWND_BINARY, SPAWND_BINARY,
			debug ? "-d" : "-n",
			"-V", verbose_level_str,
			"-i", respawn_interval_str,
			"-r", term_domain,
			"-s", script_timeout_str,
			"-k", script_kill_timeout_str,
			"-c", reopen_device,
			start_domain,
			NULL);
	exit(EXIT_FAILURE);
};

void debug_message_v(const char *fmt, va_list va) {
	FILE *out = fopen(reopen_device, "w+");
	if (!out) return;
	fprintf(out, "SPAWND: ");
	vfprintf(out, fmt, va);
	fflush(out);
	fclose(out);
};

void debug_message(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	debug_message_v(fmt, va);
	va_end(va);
};

void message(int level, const char *fmt, ...) {
	if (level > verbose_level) return;
	va_list va, va_tmp;
	va_start(va, fmt);
	va_copy(va_tmp, va);
	if (debug) {
		debug_message_v(fmt, va_tmp);
	};
	switch (log_type) {
	case LOG_TYPE_SYSLOG:
		if (4 <= verbose_level && debug) {
			debug_message("Make openlog\n");
		};
		openlog("spawnd", LOG_PID, LOG_USER);
		if (4 <= verbose_level && debug) {
			debug_message("Make vsyslog\n");
		};
		vsyslog(LOG_NOTICE, fmt, va);
		if (4 <= verbose_level && debug) {
			debug_message("Make closelog\n");
		};
		closelog();
		break;
	case LOG_TYPE_MEMORY:
		{
			size_t memory_log_free = memory_log_size - memory_log_length;
			if (!memory_log_free) goto finish;
			if (!memory_log) {
				if (!(memory_log = malloc(memory_log_size))) {
					debug_message("malloc: %s\n", strerror(errno));
					goto finish;
				};
			};
			int printed = vsnprintf(&memory_log[memory_log_length], memory_log_free, fmt, va);
			if (printed < 0) goto finish;
			if (printed >= memory_log_free) {
				printed = memory_log_free - 1;
			};
			memory_log_length += printed + 1;
		};
		break;
	default:
		break;
	};
finish:
	va_end(va_tmp);
	va_end(va);
};

int is_executable_reg(const char *path) {
	int ret=0;
	struct stat st;
	if (stat(path, &st)) goto finish;
	if (S_ISREG(st.st_mode) && (S_IXUSR & st.st_mode)) ret=1;
finish:
	return ret;
};

void service_free(struct service *service) {
	if (!service) return;
	close(service->pipe[0]);
	close(service->pipe[1]);
	free(service->name);
	charpp_free(service->depends);
	free(service);
};

struct service *service_new(const char *name, enum service_status target_status) {
	char path[1024];
	struct service *service = NULL;
	FILE *timeout_file;
	if (!(service = malloc(sizeof(struct service)))) {
		goto finish;
	};
	service->pipe[0] = -1;
	service->pipe[1] = -1;
	service->name = NULL;
	service->depends = NULL;
	if (pipe(service->pipe)) goto finish;
	snprintf(path, 1024, "%s/services/%s/depends", SPAWND_CONF_PATH, name);
	if (!(service->name = strdup(name))) goto finish_fail;
	service->depends = file_lines(path);
	if (service->depends && *service->depends && !strcmp(*service->depends, "*")) {
		service->after_all=1;
	} else {
		service->after_all=0;
	};
	service->status = SERVICE_OFF;

	service->script_timeout = script_timeout;
	service->script_kill_timeout = script_kill_timeout;
	snprintf(path, 1024, "%s/services/%s/timeout", SPAWND_CONF_PATH, name);
	if ((timeout_file = fopen(path, "r"))) {
		char timeout_line[8];
		timeout_line[0] = '\0';
		fgets(timeout_line, 32, timeout_file);
		long int service_timeout=atol(timeout_line);
		if (service_timeout<=0) {
			service->script_timeout=0;
			service->script_kill_timeout=0;
		} else {
			service->script_timeout=service_timeout;
			service->script_kill_timeout=service_timeout+(script_kill_timeout-script_timeout);
		};
		fclose(timeout_file);
	};
	service->spawn_time=0;
	service->script_time=0;
	service->spawn_term_time=0;

	service->script_pid = -1;
	service->spawn_pid = -1;
	service->target_status=target_status;
	goto finish;
finish_fail:
	service_free(service);
	service = NULL;
finish:
	return service;
};

struct service *services_find(const char *name) {
	size_t i;
	for (i=0;i<services.n;i++) {
		if (!strcmp(services.i[i]->name, name)) return services.i[i];
	};
	return NULL;
};

int service_correct(const char *name) {
	if (strlen(name) > SERVICE_NAME_MAX_LEN - 1) return 0;
	if (strchr(name, '/') ||
			name[0] == '.' ||
			strchr(name, '*') ||
			strchr(name, '\n')
		) return 0;
	struct stat st;
	char service_path[1024];
	snprintf(service_path, 1024, "%s/services/%s", SPAWND_CONF_PATH, name);
	if (stat(service_path, &st)) return 0;
	if (S_ISDIR(st.st_mode)) return 1;
	return 0;
};

int services_add(const char *name) {
	if (services_find(name)) {
		return 0;
	};
	int ret = -1;
	struct service *service = NULL;
	void *new_i = NULL;
	if (!(service = service_new(name, SERVICE_OFF))){
		message(0, "service_new: %s\n", strerror(errno));
		goto finish;
	};
	if (services.n + 1 > services.s) {
		if (!(new_i = realloc(services.i, sizeof(struct service *) * (services.s + 1)))) {
			message(0, "service_add: %s\n", strerror(errno));
			goto finish;
		};
		services.s++;
		services.i = new_i;
	};
	services.i[services.n] = service;
	service = NULL;
	services.n++;
	ret = 1;
finish:
	service_free(service);
	return ret;
};

int service_depend_of(struct service *service, const char *name) {
	char **depend=service->depends;
	if (!depend) return 0;
	for (; *depend; depend++) {
		if (!strcmp(*depend, name)) return 1;
	};
	return 0;
};

int services_set_domain(const char *domain_name) {
	if (strlen(domain_name) > DOMAIN_NAME_MAX_LEN - 1) {
		message(0, "Domain set: domain name too long\n");
		return -1;
	};
	if (strchr(domain_name, '/') ||
			domain_name[0] == '.' ||
			strchr(domain_name, '\n')
		) return -1;
	snprintf(current_domain, DOMAIN_NAME_MAX_LEN, "%s", domain_name);
	char **targets = NULL;
	char **target;
	size_t domain_path_len = strlen(SPAWND_CONF_PATH) + DOMAIN_NAME_MAX_LEN  + 10;
	char domain_path[domain_path_len];
	size_t i;
	int ret = -1;
	snprintf(domain_path, domain_path_len, "%s/domains/%s", SPAWND_CONF_PATH, domain_name);
	if (!(targets = file_lines(domain_path))) {
		message(0, "domain_set: %s: %s\n", domain_path, strerror(errno));
		goto finish;
	};
	for (target = targets; *target; target++) {
		if (service_correct(*target))
			services_add(*target);
	};
	for (i = 0; i < services.n; i++) {
		services.i[i]->target_status = SERVICE_OFF;
		for (target = targets;*target;target++) {
			if (!strcmp(*target, services.i[i]->name)) {
				services.i[i]->target_status = SERVICE_ON;
			};
		};
	};
	setup_domain = 1;
	ret = 0;
finish:
	charpp_free(targets);
	return ret;
};

pid_t service_exec(struct service *service, const char *script) {
	pid_t child = -1;
	char script_path[1024];
	char pid_env[16];
	snprintf(script_path, 1024, "%s/services/%s/%s", SPAWND_CONF_PATH, service->name, script);
	if (!is_executable_reg(script_path)) {
		child = 0;
		goto finish;
	};
	if ((child = fork()) == -1) goto finish;
	if (!child) {

		restore_signals();

		pid_env[0] = '\0';
		if (service->spawn_pid > 0) {
			snprintf(pid_env, 16, "%li", (long int)service->spawn_pid);
		};
		setenv("SPAWN_PID", pid_env, 1);

		setenv("SERVICE", service->name, 1);
		setenv("SCRIPT", script, 1);
		dup2(dummy_pipe[0], STDIN_FILENO);
		dup2(service->pipe[1], STDOUT_FILENO);
		dup2(service->pipe[1], STDERR_FILENO);

		//Prevent fds leak.
		close_all_pipes();

		//Create new process group.
		//setpgid(0, 0);
		setsid();
		tcsetpgrp(STDIN_FILENO, getpid());
		execl(script_path, script_path, NULL);
		exit(EXIT_FAILURE);
	};
	message(2, "execute script %s (%li) for %s\n", script_path, (long int)child, service->name);
finish:
	return child;
};

int check_timeout(unsigned int interval, unsigned long long int from) {
	if (from > cur_time) return 0;
	if (cur_time - from >= respawn_interval) return 1;
	return 0;
};

void setup_alarm(unsigned long long int new_alarm_time) {
	if (!alarm_time) {
		alarm_time=new_alarm_time;
		return;
	};
	if (new_alarm_time<alarm_time || alarm_time<cur_time) {
		alarm_time=new_alarm_time;
	};
	return;
};

void start_alarm() {
	if (cur_time<alarm_time) {
		alarm(alarm_time-cur_time);
	};
};

void services_process() {
	cur_time = monothonic_time();
	size_t i, j;
	struct service *service, *depend_service;
	int changed = 1;
	char **depend;
	dont_reap_childs = 0;
	while (changed) {
		changed = 0;
		for (i = 0; i < services.n; i++) {
			service = services.i[i];
			if (service->script_pid > 0 && service->script_timeout) {
				if (check_timeout(service->script_kill_timeout, service->script_time)) {
					message(2, "send KILL signal to process %li of %s\n", (long int)service->script_pid, service->name);
					kill(service->script_pid, SIGKILL);
					service->script_pid = -1;
				} else if (check_timeout(service->script_timeout, service->script_time)) {
					message(2, "send TERM signal to process %li of %s\n", (long int)service->script_pid, service->name);
					kill(service->script_pid, SIGTERM);
					setup_alarm(service->script_time+service->script_kill_timeout);
				} else {
					setup_alarm(service->script_time+service->script_timeout);
				};
			};
			if (service->spawn_pid > 0 && service->spawn_term_time) {
				if (check_timeout(service->script_kill_timeout, service->spawn_term_time)) {
					message(2, "send KILL signal to process %li of %s\n", (long int)service->spawn_pid, service->name);
					kill(service->spawn_pid, SIGKILL);
					service->spawn_pid = -1;
				};
			};
			if (service->target_status == SERVICE_ON) {
				for (j = 0; j < services.n; j++) {
					if (services.i[j]->target_status == SERVICE_OFF && services.i[j]->status != services.i[j]->target_status) {
						goto continue_1;
					};
				};
				if (service->after_all) {
					for (j = 0;j<services.n;j++) {
						if (!services.i[j]->after_all && services.i[j]->status!=services.i[j]->target_status) {
							goto continue_1;
						};
					};
				} else {
					if ((depend = service->depends)) {
						for (;*depend;depend++) {
							if (!(depend_service = services_find(*depend))) continue;
							if (depend_service->target_status == SERVICE_ON && depend_service->status != SERVICE_ON) {
								goto continue_1;
							};
						};
					};
				};
				if (service->status == SERVICE_OFF && service->script_pid <= 0) {
					service->script_pid = service_exec(service, "start");
					service->script_time = cur_time;
					service->status = SERVICE_START;
					changed = 1;
				} else if (service->status == SERVICE_FAILED && service->script_pid <= 0) {
					if (check_timeout(respawn_interval, service->spawn_time)) {
						service->script_pid = service_exec(service, "restart");
						service->script_time = cur_time;
						service->status = SERVICE_RESTART;
						changed = 1;
					} else {
						setup_alarm(service->spawn_time + respawn_interval);
					};
				} else if ((service->status == SERVICE_START) && service->script_pid <= 0) {
					if (service->spawn_pid <= 0) {
						service->spawn_pid = service_exec(service, "spawn");
						if (service->spawn_pid) {
							service->spawn_time = cur_time;
							service->spawn_term_time = 0;
						};
					};
					service->script_pid = service_exec(service, "post_start");
					service->script_time = cur_time;
					service->status = SERVICE_POST_START;
					changed = 1;
				} else if ((service->status == SERVICE_RESTART) && service->script_pid <= 0) {
					if (service->spawn_pid <= 0) {
						service->spawn_pid = service_exec(service, "spawn");
						if (service->spawn_pid) {
							service->spawn_time = cur_time;
							service->spawn_term_time = 0;
						};
					};
					service->script_pid = service_exec(service, "post_restart");
					service->script_time = cur_time;
					service->status = SERVICE_POST_RESTART;
					changed = 1;
				} else if ((service->status == SERVICE_POST_START || service->status == SERVICE_POST_RESTART) && service->script_pid <= 0) {
					service->status = SERVICE_ON;
					message(1, "service %s is enabled\n", service->name);
					changed = 1;
				} else if (service->status == SERVICE_STOP || service->status == SERVICE_POST_STOP) {
					service->status = SERVICE_OFF;
					changed = 1;
				};
			} else if (service->target_status == SERVICE_OFF || service->target_status == SERVICE_RESTART) {
				if (service->status != SERVICE_OFF && service->target_status != SERVICE_RESTART) {
					for (j = 0; j < services.n; j++) {
						if (!service->after_all
								&& service_depend_of(services.i[j], service->name)
								&& services.i[j]->status != SERVICE_OFF
								&& services.i[j]->target_status == SERVICE_OFF) {
							goto continue_1;
						};
					};
				};
				if (service->status == SERVICE_ON && service->script_pid <= 0) {
					service->script_pid = service_exec(service, "stop");
					service->script_time = cur_time;
					service->status = SERVICE_STOP;
					changed=1;
				} else if (service->status == SERVICE_STOP && service->script_pid <= 0) {
					if (service->spawn_pid <= 0) {
						service->script_pid = service_exec(service, "post_stop");
						service->script_time = cur_time;
						service->status = SERVICE_POST_STOP;
						changed = 1;
					} else {
						message(2, "send TERM signal to process %li of %s\n", (long int)service->spawn_pid, service->name);
						kill(service->spawn_pid, SIGTERM);
						service->spawn_term_time = cur_time;
						setup_alarm(cur_time + service->script_kill_timeout);
					};
				} else if (service->status == SERVICE_POST_STOP && service->script_pid <= 0) {
					service->status = SERVICE_OFF;
					if (service->target_status == SERVICE_RESTART) {
						service->target_status = SERVICE_ON;
					};
					message(1, "service %s is disabled\n", service->name);
					changed = 1;
				} else if (service->status == SERVICE_START || service->status == SERVICE_POST_START || service->status == SERVICE_FAILED || service->status == SERVICE_RESTART) {
					service->status = SERVICE_ON;
					service->spawn_time = 0;
					changed = 1;
				};
			};
continue_1:;
	   		// Dont reap childs, when start scripts executed
	   		if(service->status == SERVICE_START || service->status == SERVICE_RESTART) {
				dont_reap_childs = 1;
			};
		};
	};
	if (setup_domain) {
		size_t total_finished = 0;
		for (i = 0; i < services.n; i++) {
			service = services.i[i];
			if (service->target_status == SERVICE_ON) {
				switch (service->status) {
				case SERVICE_ON:
				case SERVICE_FAILED:
				case SERVICE_RESTART:
					total_finished++;
				default:
					break;
				};
			} else {
				switch (service->status) {
				case SERVICE_OFF:
					total_finished++;
				default:
					break;
				};
			};
		};
		
		if (total_finished == services.n) {
			//We have some magic domains
			if (!strcmp(current_domain, "reboot")) {
				reboot(LINUX_REBOOT_CMD_RESTART);
				reexec(); //If we cannot reboot, then try reexec
			} else if (!strcmp(current_domain, "halt")) {
				reboot(LINUX_REBOOT_CMD_HALT);
			} else if (!strcmp(current_domain, "poweroff")) {
				reboot(LINUX_REBOOT_CMD_POWER_OFF);
			} else if (!strcmp(current_domain, "spawnd-reexec")) {
				reexec();
			};
			setup_domain = 0;
			progress_bar();
		};

	};
	start_alarm();
	return;
};

void response(mqd_t mq_answer, struct response *resp) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 1;
	mq_timedsend(mq_answer, (void*)resp, sizeof(struct response), 0, &ts);
};

void request(struct request *req, mqd_t mq_answer) {
#define ERROR_RESPONSE(x) response(mq_answer, &((struct response) { \
	.type = RESPONSE_TYPE_ERROR, \
	.u.error.description = x \
	}));
	struct response resp;
	struct service *service;
	switch (req->type) {
	case REQUEST_TYPE_DOMAIN_SET:
		services_set_domain(req->u.domain.name);
		break;
	case REQUEST_TYPE_SERVICE_SET:
		if (!service_correct(req->u.service.name)) {
			ERROR_RESPONSE("Incorrect service name");
			goto finish;
		};
		if (services_add(req->u.service.name) < 0) {
			ERROR_RESPONSE("Internal spawnd error, check log");
			goto finish;
		};
		service = services_find(req->u.service.name);
		if (!service) {
			ERROR_RESPONSE("Internal spawnd error, check log");
			goto finish;
		};
		if (req->u.service.target_status == SERVICE_ON || req->u.service.target_status == SERVICE_OFF || req->u.service.target_status == SERVICE_RESTART) {
			service->target_status = req->u.service.target_status;
			goto finish;
		};
		if (req->u.service.spawn_pid) {
			service->spawn_pid = req->u.service.spawn_pid;
			goto finish;
		};
		break;
	case REQUEST_TYPE_DOMAIN_GET:
		resp.type = RESPONSE_TYPE_DOMAIN;
		snprintf(resp.u.domain.name, DOMAIN_NAME_MAX_LEN, "%s", current_domain);
		resp.u.domain.setup = setup_domain;
		response(mq_answer, &resp);
		break;
	case REQUEST_TYPE_SERVICE_GET:
		if (req->u.service.name[0] == '\0') {
			for (size_t ii = 0; ii < services.n; ii++) {
				if (services.i[ii]->status == SERVICE_OFF && services.i[ii]->target_status == SERVICE_OFF) continue;
				resp.type = RESPONSE_TYPE_SERVICE;
				snprintf(resp.u.service.name, SERVICE_NAME_MAX_LEN, "%s", services.i[ii]->name);
				resp.u.service.status = services.i[ii]->status;
				resp.u.service.target_status = services.i[ii]->target_status;
				resp.u.service.spawn_pid = services.i[ii]->spawn_pid;
				response(mq_answer, &resp);
			};
			goto finish;
		};
		if (!service_correct(req->u.service.name)) {
			ERROR_RESPONSE("Incorrect service name");
			goto finish;
		};
		service = services_find(req->u.service.name);
		if (!service) {
			ERROR_RESPONSE("Service not found");
			goto finish;
		};
		resp.type = RESPONSE_TYPE_SERVICE;
		snprintf(resp.u.service.name, SERVICE_NAME_MAX_LEN, "%s", service->name);
		resp.u.service.status = service->status;
		resp.u.service.target_status = service->target_status;
		resp.u.service.spawn_pid = service->spawn_pid;
		response(mq_answer, &resp);
		break;
	case REQUEST_TYPE_SPAWND_SET:
		switch (req->u.spawnd.log_type) {
		case LOG_TYPE_SYSLOG:
		case LOG_TYPE_MEMORY:
		case LOG_TYPE_NONE:
			log_type = req->u.spawnd.log_type;
			memory_log_to_log();
			message(0, "Redirect log to %s\n",
					log_type == LOG_TYPE_SYSLOG ? "syslog" :
					(log_type == LOG_TYPE_MEMORY ? "memory" : "nowhere"));
		default:
			break;
		};
		if (req->u.spawnd.debug >= 0) debug = req->u.spawnd.debug;
		if (req->u.spawnd.verbose_level >= 0) verbose_level = req->u.spawnd.verbose_level;
		break;
	case REQUEST_TYPE_KILLALL:
		;
		int pause = req->u.killall.pause;
		if (pause > 10) {
			pause = 10;
		} else if (pause < 0) {
			pause = 1;
		};
		kill(-1, SIGHUP);
		kill(-1, SIGTERM);
		kill(-1, SIGINT);
		sleep(pause);
		kill(-1, SIGKILL);
	case REQUEST_TYPE_KILL:
		if (!service_correct(req->u.kill.service_name)) {
			ERROR_RESPONSE("Incorrect service name");
			goto finish;
		};
		service = services_find(req->u.kill.service_name);
		if (!service) {
			ERROR_RESPONSE("Service not found");
			goto finish;
		};
		if (service->spawn_pid > 0) {
			kill(service->spawn_pid, req->u.kill.signal);
		};
		break;
	default:
		response(mq_answer, &((struct response) {
				.type = RESPONSE_TYPE_ERROR,
				.u.error.description = "Unknown request type"
				}));
		break;
	};

finish:

	return;
#undef ERROR_RESPONSE
};

void mq_check() {
	message(4, "Check message queue\n");
	struct request req;
	ssize_t bytes_read;
	while ((bytes_read = mq_receive(mq, (void*)&req, sizeof(struct request), NULL)) > 0) {
		message(4, "Get message\n");
		mqd_t mq_resp = (mqd_t)-1;
		if (bytes_read < 0) {
			message(0, "mq_receive: %s", strerror(errno));
			goto next;
		};
		if (bytes_read != sizeof(struct request)) {
			message(0, "Incorrect request", strerror(errno));
			goto next;
		};
		req.end = '\0'; //Just in case
		req.callback_mq_name[sizeof(req.callback_mq_name) - 1] = '\0';
		if (strncmp(req.callback_mq_name, "/spawndctl", 10)) {
			message(0, "Incorrect queue name in request");
			goto next;
		};
		if ((mq_resp = mq_open(req.callback_mq_name, O_WRONLY)) == (mqd_t)-1) {
			message(0, "mq_open: %s :%s", req.callback_mq_name, strerror(errno));
			goto next;
		};
		request((void*)&req, mq_resp);
		struct response response_end;
		response_end.type = RESPONSE_TYPE_END;
		response(mq_resp, (void*)&response_end);
next:
		mq_unlink(req.callback_mq_name);
		if (mq_resp != (mqd_t)-1) {
			mq_close(mq_resp);
		};
	};
	struct sigevent ev;
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;
	mq_notify(mq, &ev);
};

void signal_handler(int signal) {
	if (reexec_lock) return;
	switch(signal) {
	case SIGUSR1:
		message(3, "USR1\n");
		//usr_handler();
		break;
	case SIGALRM:
		message(3, "ALRM\n");
		alarm_time = 0;
		break;
	case SIGINT:
		message(3, "INT\n");
		services_set_domain(term_domain);
		break;
	case SIGTERM:
		message(3, "TERM\n");
		progress_bar();
		break;
	case SIGCHLD:
		message(3, "CHLD\n");
		break;
	};
	mq_check();
	child_handler();
};

void fd_to_message(int fd, const char *title) {
	char message_line[MESSAGE_LINE_SIZE];
	size_t readed;
	readed = read(fd, message_line, MESSAGE_LINE_SIZE - 1);
	if (readed < 0) return;
	message_line[readed] = '\0';
	message(0, "%s: %s", title, message_line);
};

int main(int argc, char **argv) {
	ctl_socket = -1;
	dont_reap_childs = 0;
	log_type = LOG_TYPE_MEMORY;
	memory_log = NULL;
	memory_log_length = 0;
	memory_log_size = MEMORY_LOG_SIZE;
	setup_domain = 1;
	reexec_lock = 0;
	debug = 0;
	verbose_level = 1;
	term_domain = "reboot";
	setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin", 1);
	alarm_time = 0;
	int opt;
	self_pid = getpid();
	respawn_interval = 10;
	script_timeout = 10;
	script_kill_timeout = 10;
	services.i = NULL;
	services.n = 0;
	services.s = 0;
	start_domain = "default";
	reopen_device = "/dev/console";
	chdir("/");

	reboot(LINUX_REBOOT_CMD_CAD_OFF);

	cur_time = monothonic_time();

	while ((opt = getopt(argc, argv, "i:s:S:k:r:c:V:vdnq")) != -1) {
		switch(opt) {
		case 'i':
			respawn_interval = atoi(optarg);
			if (respawn_interval <= 0) {
				respawn_interval = 10;
			};
			break;
		case 's':
			script_timeout=atoi(optarg);
			if (script_timeout <= 0) {
				script_timeout = 10;
			};
			break;
		case 'S':
			break;
		case 'k':
			script_kill_timeout = atoi(optarg);
			if (script_kill_timeout<0) {
				script_kill_timeout = 10;
			};
			break;
		case 'r':
			term_domain = optarg;
			break;
		case 'v':
			verbose_level++;
			break;
		case 'd':
			debug = 1;
			break;
		case 'n':
			debug = 0;
			break;
		case 'q':
			verbose_level--;
			break;
		case 'c':
			reopen_device = optarg;
			break;
		case 'V':
			verbose_level = atoi(optarg);
		default:
			//ignore unknown options
			break;
		};
	};
	script_kill_timeout += script_timeout;

	int real_argc = argc - optind;
	char **real_argv = &argv[optind];

	if (real_argc) {
		start_domain = real_argv[0];
	};

	services_set_domain(start_domain);

	struct sigaction act;

	struct sigaction ign_act;
	sigset_t empty_sigset;

	sigemptyset(&block_signals);
	sigemptyset(&empty_sigset);
	sigaddset(&block_signals, SIGCHLD);
	sigaddset(&block_signals, SIGUSR1);
	sigaddset(&block_signals, SIGALRM);
	sigaddset(&block_signals, SIGTERM);
	sigaddset(&block_signals, SIGINT);

	act.sa_handler = signal_handler;
	act.sa_mask = block_signals;
	act.sa_flags = 0;

	ign_act.sa_handler = SIG_IGN;
	ign_act.sa_mask = empty_sigset;
	ign_act.sa_flags = 0;

	struct mq_attr attr;
	attr.mq_flags = 0;
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = sizeof(struct request);
	attr.mq_curmsgs = 0;
	mq_unlink(MQ_SPAWND_NAME);
	while ((mq = mq_open(MQ_SPAWND_NAME, O_CREAT | O_RDONLY | O_NONBLOCK | O_EXCL,
			0600, &attr)) == (mqd_t)-1) {
		//What should we do?
		sleep(1);
	};
	struct sigevent ev;
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;
	while (mq_notify(mq, &ev) == -1) {
		//What should we do?
		sleep(1);
	};

	sigaction(SIGCHLD, &act, &old_chld_act);
	sigaction(SIGUSR1, &act, &old_usr1_act);
	sigaction(SIGALRM, &act, &old_alrm_act);
	sigaction(SIGTERM, &act, &old_term_act);
	sigaction(SIGINT, &act, &old_int_act);

	sigaction(SIGHUP, &ign_act, &old_hup_act);
	sigaction(SIGPIPE, &ign_act, &old_pipe_act);

	while (pipe(dummy_pipe)) {
		//What should we do?
		sleep(1);
	};
	dup2(dummy_pipe[0], STDIN_FILENO);
	dup2(dummy_pipe[1], STDOUT_FILENO);
	dup2(dummy_pipe[1], STDERR_FILENO);
	int poll_ret;
	int nfds;
	size_t i;
	kill(getpid(), SIGALRM);
	sigprocmask(SIG_BLOCK, &block_signals, NULL);
	for (;;) {
		nfds = services.n + 1;
		struct pollfd fds[nfds];
		fds[0].fd = dummy_pipe[0];
		fds[0].events = POLLIN;
		for (i = 0; i < services.n; i++) {
			fds[i + 1].fd = services.i[i]->pipe[0];
			fds[i + 1].events = POLLIN;
		};
		message(4, "Wait fd or signal.\n");
		sigprocmask(SIG_UNBLOCK, &block_signals, NULL);
		poll_ret = poll(fds, nfds, -1);
		sigprocmask(SIG_BLOCK, &block_signals, NULL);
		if (poll_ret <= 0) {
			if (!poll_ret) {
				message(0, "poll: no activity\n");
			} else {
				message(errno == EINTR ? 3 : 0, "poll: %s\n", strerror(errno));
			};
			continue;
		};
		for (i = 0; i < services.n; i++) {
			if (fds[i + 1].revents & POLLIN) {
				message(4, "Got message from %s\n", services.i[i]->name);
				fd_to_message(services.i[i]->pipe[0], services.i[i]->name);
			};
		};
	};
	return EXIT_FAILURE;
};
