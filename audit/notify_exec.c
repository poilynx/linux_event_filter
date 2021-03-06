#include <sys/types.h>
#include <libaudit.h>
#include <signal.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int fd = -1;
struct audit_rule_data *rule = NULL;

void sig_handler(int sig)
{
	if (rule) {
		audit_delete_rule_data(fd, rule, AUDIT_FILTER_TASK, AUDIT_ALWAYS);
		audit_close(fd);
	}
	exit(0);
}

void set_sighandler()
{
	struct sigaction sa;
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
}

int main()
{
	printf("filter all process related system call\n\n");
	set_sighandler();

	fd = audit_open();
	if (fd <= 0) {
		perror("audit_open");
		exit(-1);
	}

	rule = malloc(sizeof(struct audit_rule_data));
	memset(rule, 0, sizeof (struct audit_rule_data));


	if (audit_add_rule_data(fd, rule, AUDIT_FILTER_TASK, AUDIT_ALWAYS) < 0) {
		perror("audit_add_rule_data");
		exit(-1);
	}
	if (audit_set_pid(fd, getpid(), WAIT_YES) <= 0) {
		perror("audit_set_pid");
		sig_handler(0);
	}
	audit_set_enabled(fd, 1);

	while (1) {
		struct audit_reply reply;
		char buf[MAX_AUDIT_MESSAGE_LENGTH];
		audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
		snprintf(buf, MAX_AUDIT_MESSAGE_LENGTH,
				"Type=%s Message=%.*s",
				audit_msg_type_to_name(reply.type),
				reply.len,
				reply.message);

		printf("event: %s\n", buf);

	}
}
