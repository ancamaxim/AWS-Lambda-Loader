// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipc.h"

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

int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket() failed");

	return sockfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	struct sockaddr_un addr;
	int connectfd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);

	connectfd = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	return connectfd;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	return -1;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	return -1;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */

}
