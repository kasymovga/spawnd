#define _POSIX_SOURCE
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#define PROC_PATH "/proc"
#define IGNORE_PIDS_MAX_COUNT 256
#define BUFFER_LEN 1024
#define PROC_FILE_PATH_LEN 1024

const char *proc_path;
const char *cmd;

void usage() {
	fprintf(stderr,
			"%s [signal]\n"
			,cmd
			);
};

struct pid_pair {
	pid_t child, parent;
};

pid_t get_proc_parent(pid_t pid) {
	pid_t ret = -1;
	char proc_stat_path[PROC_FILE_PATH_LEN];
	char buffer[BUFFER_LEN];
	FILE *proc_stat_file = NULL;
	const char *parent_pid;
	snprintf(proc_stat_path, PROC_FILE_PATH_LEN, "%s/%lli/stat", proc_path, (long long int)pid);
	if(!(proc_stat_file = fopen(proc_stat_path,"r"))) goto finish;
	if(!fgets(buffer, BUFFER_LEN, proc_stat_file)) goto finish;

	if(!(parent_pid = strrchr(buffer,')'))) goto finish;
	if(strlen(parent_pid) < 4) goto finish;
	parent_pid = &parent_pid[4];
	ret = atol(parent_pid);
finish:
	if(proc_stat_file) fclose(proc_stat_file);
	return ret;
};

int killall(int signal, pid_t*ignore_pids, unsigned int ignore_pids_count) {
	int ret = -1;
	DIR*proc_dir = NULL;
	struct dirent *dirent;
	pid_t pid;
	unsigned int i;
	if(!(proc_dir = opendir(PROC_PATH))) {
		goto finish;
	};
	while((dirent = readdir(proc_dir))) {
		if(!(pid = atoll(dirent->d_name))) continue;
		for(i = 0; i < ignore_pids_count; i++) {
			if(pid == ignore_pids[i]) {
				//printf("skip %lli\n",(long long int)pid);
				goto continue_1;
			};
		};
		//printf("kill %lli\n",(long long int)pid);
		kill(pid, signal);
continue_1:;
	};
	ret = 0;
finish:
	if(proc_dir) closedir(proc_dir);
	return ret;
};

int main(int argc,char **argv) {
	cmd = argv[0]?argv[0]:"wtf?";
	int ret = EXIT_FAILURE;
	int signal = SIGTERM;
	pid_t ignore_pid;
	int real_argc;
	char **real_argv;
	
	pid_t ignore_pids[IGNORE_PIDS_MAX_COUNT];
	unsigned int ignore_pids_count = 0;
	int opt;
	proc_path = PROC_PATH;

	while((opt = getopt(argc, argv, "p:")) !=- 1) {
		switch(opt) {
		case 'p':
			proc_path = optarg;
			break;
		default:
			usage();
			goto finish;
		};
	};

	real_argc = argc - optind;
	real_argv = &argv[optind];


	ignore_pid = getpid();

	for(ignore_pids_count = 0; ignore_pids_count <= IGNORE_PIDS_MAX_COUNT && ignore_pid > 0;) {
		ignore_pids[ignore_pids_count++] = ignore_pid;
		ignore_pid = get_proc_parent(ignore_pid);
	};

	if(ignore_pids_count && ignore_pid > 0) {
		fprintf(stderr,"%s: self process is to deep\n",cmd);
		goto finish;
	};

	if(ignore_pid < 0) {
		fprintf(stderr,"%s: cannot define self location\n",cmd);
		goto finish;
	};

	if(real_argc == 1) {
		if(!strcmp(real_argv[0], "TERM")) {
			signal = SIGTERM;
		} else if(!strcmp(real_argv[0], "KILL")) {
			signal = SIGKILL;
		} else if(!strcmp(real_argv[0], "INT")) {
			signal = SIGINT;
		} else if(!strcmp(real_argv[0], "HUP")) {
			signal = SIGHUP;
		} else if(!strcmp(real_argv[0], "ALRM")) {
			signal = SIGALRM;
		} else if(!strcmp(real_argv[0], "USR1")) {
			signal = SIGUSR1;
		} else if(!strcmp(real_argv[0], "USR2")) {
			signal = SIGUSR2;
		} else {
			signal = atoi(real_argv[0]);
		};
		signal = atoi(real_argv[0]);
	} else if (real_argc > 1) {
		goto finish;
	};

	killall(signal, ignore_pids, ignore_pids_count);

	ret = EXIT_SUCCESS;
finish:
	return ret;
};
