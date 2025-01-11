/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _IPC_H
#define _IPC_H

/* ssize_t */
#include <sys/types.h>
#include <errno.h>

#define BUFSIZE 1024
#define MAX_CLIENTS 1024
#define SOCKET_NAME "/tmp/sohack.socket"
#define IP "127.0.0.1"
#define PORT 5555

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);					\
		}							\
	} while (0)

int create_socket(void);
int create_inet_socket(void);
int connect_socket(int fd);
int connect_inet_socket(int fd);
ssize_t send_socket(int fd, const char *buf, size_t len);
ssize_t recv_socket(int fd, char *buf, size_t len);
void close_socket(int fd);

#endif /* _IPC_H */
