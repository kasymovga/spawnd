#include "common.h"
#define MQ_NAME_MAX_LEN 128
#define ERROR_DESCRIPTION_MAX_LEN 128
#define MQ_SPAWND_NAME "/spawnd"

enum request_type {
	REQUEST_TYPE_EMPTY,
	REQUEST_TYPE_SERVICE_SET,
	REQUEST_TYPE_SERVICE_GET,
	REQUEST_TYPE_DOMAIN_SET,
	REQUEST_TYPE_DOMAIN_GET,
	REQUEST_TYPE_SPAWND_SET,
	REQUEST_TYPE_SPAWND_GET,
	REQUEST_TYPE_KILL,
	REQUEST_TYPE_KILLALL,
	REQUEST_TYPE_ENUM_END
};

enum response_type {
	RESPONSE_TYPE_SERVICE,
	RESPONSE_TYPE_DOMAIN,
	RESPONSE_TYPE_SPAWND,
	RESPONSE_TYPE_ERROR,
	RESPONSE_TYPE_END,
	RESPONSE_TYPE_ENUM_END
};

struct message_service {
	char name[SERVICE_NAME_MAX_LEN];
	long long int spawn_pid;
	enum service_status status;
	enum service_status target_status;
};

struct message_spawnd {
	short int debug;
	short int verbose_level;
	enum log_type log_type;
};

struct message_domain {
	char name[DOMAIN_NAME_MAX_LEN];
	short int setup;
};

struct message_killall {
	int pause;
};

struct message_kill {
	int signal;
	char service_name[SERVICE_NAME_MAX_LEN];
};

struct message_error {
	char description[ERROR_DESCRIPTION_MAX_LEN];
};

struct request {
	enum request_type type;
	char callback_mq_name[MQ_NAME_MAX_LEN];
	union {
		struct message_service service;
		struct message_spawnd spawnd;
		struct message_domain domain;
		struct message_killall killall;
		struct message_kill kill;
	} u;
	char end;
};

struct response {
	enum response_type type;
	union {
		struct message_service service;
		struct message_spawnd spawnd;
		struct message_domain domain;
		struct message_error error;
	} u;
	char end;
};
