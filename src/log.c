#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

static int log_fd;
static const char *log_info = "INFO: ";
static const char *log_debug = "DEBUG: ";
static const char *log_warning = "WARNING: ";

void create_log(char *filename)
{
    log_fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
}

void dlog(char *message, enum log_t log)
{
    switch (log)
	{
	case INFO:
		write(log_fd, log_info, sizeof(log_info));
		break;
	case DEBUG:
		write(log_fd, log_debug, sizeof(log_debug));
		break;
	case WARNING:
		write(log_fd, log_warning, sizeof(log_warning));
		break;
	default:
		break;
	}

	write(log_fd, message, strlen(message));
}

void remove_log(void)
{
    close(log_fd);
}
