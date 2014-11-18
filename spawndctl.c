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
#include "common.h"

const char * cmd;
const char *mq_name;

void usage() {
	printf(
			"%s [-p pid] <command>\n"
			,cmd);
};

int spawndctl(int argc, char **argv) {
	int ret = -1;
#if 0
	char *ret = NULL;
	FILE *in = NULL, *out = NULL;
	int i;
	for (i = 0; i < 3; i++) {
		kill(spawnd_pid, SIGUSR1);
		alarm(1);
		if(!(in = fopen(SPAWND_CONF_PATH"/in", "w"))) continue;
		break;
	};
	if (!in) goto finish;

	for (i = 0; i < argc; i++) {
		if (fprintf(in, "%s ", argv[i])<0) goto finish;
	};
	if (fprintf(in, "\n") < 0) goto finish;
	fflush(in);

	alarm(1);
	if (!(out = fopen(SPAWND_CONF_PATH"/out","r"))) goto finish;
	
	ret = mgets(out);
finish:
	if (in) fclose(in);
	if (out) fclose(out);
#endif
	mqd_t mq = (mqd_t)-1, mq_answer = (mqd_t)-1;
	if ((mq = mq_open(mq_name, 0)) == (mqd_t)-1) goto finish;
	char answer_queue_name[128];
	snprintf(answer_queue_name, 128, "/spawndctl%li", (long int)getpid());
	struct mq_attr attr;
	attr.mq_flags = 0;
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = 1024;
	attr.mq_curmsgs = 0;
	mq_answer = mq_open(answer_queue_name, O_CREAT | O_EXCL | O_RDONLY, 0600,
			&attr);
	if (mq_answer == (mqd_t)-1) goto finish;
#define BUFFER_SIZE 1024
	char answer[BUFFER_SIZE + 1];
	ssize_t readed;
	while ((readed = mq_receive(mq_answer, answer, BUFFER_SIZE, NULL)) !=
			(mqd_t)-1) {
		answer[readed] = '\0';
		if (!*answer) {
			ret = 0;
			break;
		};
		printf("%s\n",answer);
	};
finish:
	if (mq != (mqd_t)-1) {
		mq_close(mq);
		mq_unlink(answer_queue_name);
	};
	if (mq_answer != (mqd_t)-1)
		mq_close(mq);
	return ret;
};

int main( int argc, char **argv ) {
	char *answer = NULL;
	mq_name = "/spawnd";
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
		if(spawndctl(real_argc, real_argv)) {
			fprintf(stderr, "%s: %s\n", cmd, strerror(errno));
			goto finish;
		};
	};
	ret = EXIT_SUCCESS;
finish:
	free(answer);
	return ret;
};
