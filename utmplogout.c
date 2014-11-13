#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <utmp.h>
#include <sys/time.h>
#include <sys/types.h>

const char *cmd;

void usage() {
	fprintf(stderr, "%s [line] [pid]\n", cmd);
};

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;
	cmd = (argc && argv[0]) ? argv[0] : "wtf?";
	if (argc != 3) {
		usage();
		goto finish;
	};

	const char *line = argv[1];
	pid_t pid  = atol(argv[2]);

	struct utmp ut;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	ut.ut_tv.tv_sec = tv.tv_sec;
	ut.ut_tv.tv_usec = tv.tv_usec;
	ut.ut_type = DEAD_PROCESS;
	ut.ut_pid = pid;
	memset(ut.ut_user, 0, UT_NAMESIZE);
	strncpy(ut.ut_line, line, UT_LINESIZE);
	ut.ut_line[UT_LINESIZE-1] = 0;
	memset(ut.ut_id, 0, 4);
	memset(ut.ut_host, 0, UT_HOSTSIZE);
	ut.ut_session = 0;

	updwtmp("/var/log/wtmp", &ut);
	logout(line);
finish:
	return ret;
};
