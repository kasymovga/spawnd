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
#include "config.h"
#include "misc.h"

const char * cmd;
pid_t spawnd_pid;

void usage() {
	printf(
			"%s [-p pid] <command>\n"
			,cmd);
};

char *spawndctl(int argc, char **argv) {
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
	return ret;
};

int main( int argc, char **argv ) {
	char *answer = NULL;
	spawnd_pid = 1;
	int ret = EXIT_FAILURE;
	cmd = (argc && argv[0]) ? argv[0] : "wtf?";
	int opt;
	while ((opt = getopt(argc,argv,"p:")) != -1) {
		switch(opt) {
		case 'p':
			spawnd_pid = atol(optarg);
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
		if(!(answer = spawndctl(real_argc, real_argv))) {
			fprintf(stderr, "%s: %s\n", cmd, strerror(errno));
			goto finish;
		};
		printf("%s\n",answer);
	};
	ret = EXIT_SUCCESS;
finish:
	free(answer);
	return ret;
};
