#define _POSIX_SOURCE
#include <sys/types.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <mqueue.h>
#include "config.h"
//#include "misc.h"
#include "ipc.h"

const char *cmd;
const char *errormsg;
#define ERROR_MSG_BUF_SIZE 128
char errormsg_buf[ERROR_MSG_BUF_SIZE];
const char *mq_name;

void usage() {
	printf(
			"%s [-m <mq name>] <command>\n"
			,cmd);
};

const char *service_status(enum service_status status) {
	const char *status_str;
	switch (status) {
	case SERVICE_ON:
		status_str = "ON";
		break;
	case SERVICE_OFF:
		status_str = "OFF";
		break;
	case SERVICE_FAILED:
		status_str = "FAILED";
		break;
	case SERVICE_START:
		status_str = "START";
		break;
	case SERVICE_POST_START:
		status_str = "POST_START";
		break;
	case SERVICE_STOP:
		status_str = "STOP";
		break;
	case SERVICE_POST_STOP:
		status_str = "POST_STOP";
		break;
	default:
		status_str = "Unknown";
	};
	return status_str;
};

int spawndctl(struct request *req) {
	int ret = -1, error_status = 0;
	mqd_t mq_req = (mqd_t)-1, mq_resp = (mqd_t)-1;
	if ((mq_req = mq_open(mq_name, O_WRONLY)) == (mqd_t)-1) {
		snprintf(errormsg_buf, ERROR_MSG_BUF_SIZE, "mq_open: %s", strerror(errno));
		errormsg = errormsg_buf;
		goto finish;
	};
	snprintf(req->callback_mq_name, MQ_NAME_MAX_LEN, "/spawndctl%li", (long int)getpid());
	struct mq_attr attr;
	attr.mq_flags = 0;
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = sizeof(struct response);
	attr.mq_curmsgs = 0;
	mq_resp = mq_open(req->callback_mq_name, O_CREAT | O_EXCL | O_RDONLY, 0600,
			&attr);
	if (mq_resp == (mqd_t)-1) {
		snprintf(errormsg_buf, ERROR_MSG_BUF_SIZE, "mq_open: %s", strerror(errno));
		errormsg = errormsg_buf;
		goto finish;
	};

	if (mq_send(mq_req, (void*)req, sizeof(struct request), 0)) {
		snprintf(errormsg_buf, ERROR_MSG_BUF_SIZE, "mq_send: %s", strerror(errno));
		errormsg = errormsg_buf;
		goto finish;
	};
	struct response resp;
	ssize_t readed;
	while ((readed = mq_receive(mq_resp, (void*)&resp, sizeof(struct response), NULL)) ==
			sizeof(struct response)) {
		resp.end = '\0'; //just in case
		switch (resp.type) {
		case RESPONSE_TYPE_END:
			ret = error_status;
			goto finish;
		case RESPONSE_TYPE_SERVICE:
			printf("%s/%s/%s/%lli\n", resp.u.service.name, service_status(resp.u.service.status),
					service_status(resp.u.service.target_status), (long long int)resp.u.service.spawn_pid);
			break;
		case RESPONSE_TYPE_DOMAIN:
			printf("Domain name: %s\n", resp.u.domain.name);
			printf("Domain status: %s\n", resp.u.domain.setup ? "setuping" : "reached");
			break;
		case RESPONSE_TYPE_ERROR:
			printf("Error: %s\n", resp.u.error.description);
			error_status = -1;
			errormsg = "Spawnd return error.";
			break;
		default:
			printf("Unknown response type\n");
			goto finish;
		};
	};
	if (readed < 0) {
		snprintf(errormsg_buf, ERROR_MSG_BUF_SIZE, "mq_receive: %s", strerror(errno));
		errormsg = errormsg_buf;
		goto finish;
	};
	errormsg = "Incorrect answer from spawnd";
finish:
	mq_unlink(req->callback_mq_name);
	if (mq_req != (mqd_t)-1) {
		mq_close(mq_req);
	};
	if (mq_resp != (mqd_t)-1) {
		mq_close(mq_resp);
	};
	return ret;
};

int spawndctl_prepare(int argc, char **argv) {
	struct request req = {.type = REQUEST_TYPE_EMPTY};
	int ret = -1;
	if (argc == 0) {
		errormsg = "No command";
		goto finish;
	};
	if (!strcmp(argv[0], "start") && argc == 2) {
		req.type = REQUEST_TYPE_SERVICE_SET;
		req.u.service.target_status = SERVICE_ON;
		req.u.service.spawn_pid = 0;
		snprintf(req.u.service.name, SERVICE_NAME_MAX_LEN, "%s", argv[1]);
	} else if (!strcmp(argv[0], "stop") && argc == 2) {
		req.type = REQUEST_TYPE_SERVICE_SET;
		req.u.service.target_status = SERVICE_OFF;
		req.u.service.spawn_pid = 0;
		snprintf(req.u.service.name, SERVICE_NAME_MAX_LEN, "%s", argv[1]);
	} else if (!strcmp(argv[0], "status") && argc <= 2) {
		req.type = REQUEST_TYPE_SERVICE_GET;
		if (argc == 1) {
			req.u.service.name[0] = '\0';
		} else {
			snprintf(req.u.service.name, SERVICE_NAME_MAX_LEN, "%s", argv[1]);
		};
	} else if (!strcmp(argv[0], "domain") && argc <= 2) {
		if (argc == 1) {
			req.type = REQUEST_TYPE_DOMAIN_GET;
		} else {
			req.type = REQUEST_TYPE_DOMAIN_SET;
			snprintf(req.u.service.name, DOMAIN_NAME_MAX_LEN, "%s", argv[1]);
		};
	} else if ((!strcmp(argv[0], "set_spawn_pid") || !strcmp(argv[0], "spawn_pid")) && argc == 3) {
		req.type = REQUEST_TYPE_SERVICE_SET;
		req.u.service.target_status = SERVICE_DONTCHANGE;
		snprintf(req.u.service.name, SERVICE_NAME_MAX_LEN, "%s", argv[1]);
		req.u.service.spawn_pid = atoll(argv[2]);
	} else if (!strcmp(argv[0], "log") && argc == 2) {
		req.type = REQUEST_TYPE_SPAWND_SET;
		if (!strcmp(argv[1], "syslog")) {
			req.u.spawnd.log_type = LOG_TYPE_SYSLOG;
		} else if (!strcmp(argv[1], "memory")) {
			req.u.spawnd.log_type = LOG_TYPE_MEMORY;
		} else if (!strcmp(argv[1], "none")) {
			req.u.spawnd.log_type = LOG_TYPE_NONE;
		} else {
			errormsg = "Unknown syslog type";
			goto finish;
		};
		req.u.spawnd.debug = -1;
		req.u.spawnd.verbose_level = -1;
	} else if (!strcmp(argv[0], "debug") && argc == 2) {
		req.type = REQUEST_TYPE_SPAWND_SET;
		req.u.spawnd.log_type = LOG_TYPE_DONTCHANGE;
		req.u.spawnd.debug = atoi(argv[1]);
		req.u.spawnd.verbose_level = -1;
	} else if (!strcmp(argv[0], "verbose_level") && argc == 2) {
		req.type = REQUEST_TYPE_SPAWND_SET;
		req.u.spawnd.log_type = LOG_TYPE_DONTCHANGE;
		req.u.spawnd.debug = -1;
		req.u.spawnd.verbose_level = atoi(argv[1]);
	} else if (!strcmp(argv[0], "killall") && argc == 2) {
		req.type = REQUEST_TYPE_KILLALL;
		req.u.killall.pause = atoi(argv[1]);
	} else {
		errormsg = "Wrong command";
		goto finish;
	};
	ret = spawndctl(&req);
finish:
	return ret;
};

int main( int argc, char **argv ) {
	errormsg = "Unknown error";
	mq_name = MQ_SPAWND_NAME;
	int ret = EXIT_FAILURE;
	cmd = (argc && argv[0]) ? argv[0] : "wtf?";
	int opt;
	while ((opt = getopt(argc,argv,"m:")) != -1) {
		switch(opt) {
		case 'm':
			mq_name = optarg;
			break;
		default:
			usage();
			goto finish;
			break;
		};
	};
	int real_argc = argc - optind;
	char **real_argv = &argv[optind];

	if(!real_argc) {
		usage();
		goto finish;
	} else {
		if(spawndctl_prepare(real_argc, real_argv)) {
			fprintf(stderr, "%s: %s\n", cmd, errormsg);
			goto finish;
		};
	};
	ret = EXIT_SUCCESS;
finish:
	return ret;
};
