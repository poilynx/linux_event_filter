#include <unistd.h>
#include <sys/inotify.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define MAX_EVENTS 128
#define BUFFER_SIZE (MAX_EVENTS * ( EVENT_SIZE + 16))

static char* get_type_string(struct inotify_event *e, char *buf)
{
	buf[0] = '\0';
	if (e->mask & IN_ACCESS)        strcat(buf, "|IN_ACCESS");
	if (e->mask & IN_ATTRIB)        strcat(buf, "|IN_ATTRIB");
	if (e->mask & IN_CLOSE_NOWRITE) strcat(buf, "|IN_CLOSE_NOWRITE");
	if (e->mask & IN_CLOSE_WRITE)   strcat(buf, "|IN_CLOSE_WRITE");
	if (e->mask & IN_CREATE)        strcat(buf, "|IN_CREATE");
	if (e->mask & IN_DELETE)        strcat(buf, "|IN_DELETE");
	if (e->mask & IN_DELETE_SELF)   strcat(buf, "|IN_DELETE_SELF");
	if (e->mask & IN_IGNORED)       strcat(buf, "|IN_IGNORED");
	if (e->mask & IN_ISDIR)         strcat(buf, "|IN_ISDIR");
	if (e->mask & IN_MODIFY)        strcat(buf, "|IN_MODIFY");
	if (e->mask & IN_MOVE_SELF)     strcat(buf, "|IN_MOVE_SELF");
	if (e->mask & IN_MOVED_FROM)    strcat(buf, "|IN_MOVED_FROM");
	if (e->mask & IN_MOVED_TO)      strcat(buf, "|IN_MOVED_TO");
	if (e->mask & IN_OPEN)          strcat(buf, "|IN_OPEN");
	if (e->mask & IN_Q_OVERFLOW)    strcat(buf, "|IN_Q_OVERFLOW");
	if (e->mask & IN_UNMOUNT)       strcat(buf, "|IN_UNMOUNT");
	return buf;
}


int main()
{
	int fd, wd;
	char buffer[2048];

	fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init");
	}

	wd = inotify_add_watch(fd, "/tmp", IN_ALL_EVENTS);
	if (wd < 0) {
		perror("inotify_add_watch");
	}


	for (;;) {
		ssize_t retlen = read(fd, buffer, sizeof buffer);
		if (retlen < 0) {
			perror("read");
			exit(1);
		}
		for(char *p = buffer; p < buffer + retlen;) {
			char type[256];
			struct inotify_event *event = (struct inotify_event *) p;
			get_type_string(event, type);
			printf("%s\t%s\n", type + 1, event->name);
			p += sizeof(struct inotify_event) + event->len;
		}
	}

	inotify_rm_watch(fd, wd);
	close(fd);
	return 0;
}
