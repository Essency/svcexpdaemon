/****************************************************************
 * 		Azzurra IRC Services Export Daemon		*
 ****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 20 * ( EVENT_SIZE + 16 ) )

#define DEFAULT_DB_PATH "data/"

int     fd, wd;
char    buffer[BUF_LEN];
int     cs_saved = 0, ns_saved = 0;
char    *db_path = DEFAULT_DB_PATH;

static void read_loop(void);
extern void export_dbs(const char *base_path);

static struct option long_options[] = { 
	{"data-dir",	required_argument,	NULL,	'd'},
	{"help",	no_argument,		NULL,	'h'},
	{"foreground",	no_argument,		NULL,	'f'},
//	{"otrs",	no_argument,		NULL,	'o'}, /*We don't use it anymore...useless*/
	{NULL}
};
static const char usage[] =
	"Azzurra IRC Service Export Daemon\r\n"
	"Usage:\r\n"
	"-d --data-dir \t - Set the datadir where nick.db and chan.db are located (Default: data/)\r\n"
	"-f --foreground \t - Don't fork()\r\n"
	"-h --help \t - Show this Help\r\n";

int main(int argc, char **argv) {
	pid_t	pid = 0;
	int	opt, opt_idx, f = 1;

	printf("Azzurra IRC Services Export Daemon\r\n");

	while(1) {
		opt = getopt_long(argc, argv, "d:fh", long_options, &opt_idx);
		if (opt == EOF)
			break;
		switch(opt) {
			case 'd':
				db_path = strdup(optarg);
				break;
			case 'h':
			        printf("%s", usage);
			        return 0;
			case 'f':
				f = 0;
		}
	}

	if (f == 1) {
		printf("Now forking...\r\n");
		pid = fork();

		if (pid > 0)
			return 0; /*parent*/
		else if (pid == -1) {
			perror("Unable to fork()");
			return 1;
		}
		if (setpgid(0, 0) < 0) {
			perror("stdpgid()");
			return 1;
		}
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
	/*child..*/

	fd = inotify_init();
	
	if (fd < 0) {
		perror("inotify_init()");
		return 1;
	}

	wd = inotify_add_watch(fd, db_path, IN_CLOSE_WRITE);
	if (wd < 0) {
		perror("inotify_add_watch()");
		return 1;
	}
	read_loop();
	return 0;
}

static void read_loop() {
	struct inotify_event	*event;
	char			buf[BUF_LEN];
	int			i, len;
	while (1) {
		i = 0;
		len = read(fd, buf, BUF_LEN);
		if (len < 0) {
			if (errno == EINTR)
				continue; /*system call was interrupted by a signal, just retry*/
			else {
				perror("read()");
				exit(1);
			}
		} else if (!len) {
			fprintf(stderr, "Error, read() == 0");
			exit(1);
		}
		while (i < len) {
			event = (struct inotify_event *) &buf[i];
			i += EVENT_SIZE + event->len;
			if (event->mask & IN_CLOSE_WRITE) {
				if (!strcasecmp(event->name, "chan.db"))
					cs_saved = 1;
				else if (!strcasecmp(event->name, "nick.db"))
					ns_saved = 1;
				if (ns_saved && cs_saved) {
					ns_saved = 0;
					cs_saved = 0;
					
					printf("Export...\r\n");
					export_dbs(db_path);
				}
			}

		}
	}
}
