#include <utmp.h>
#include <stdlib.h>
#include <stdio.h>

const char *cmd;

void usage() {
	printf("Usage: %s <line> <name> <host>\n", cmd);
};

int main(int argc, char **argv) {
	cmd = argc ? (argv[0] ? argv[0] : "") : "";
	int ret = EXIT_FAILURE;
	if(argc != 4) {
		usage();
		goto finish;
	}
	logwtmp(argv[1], argv[2], argv[3]);
	ret = EXIT_SUCCESS;
finish:
	return ret;
};
