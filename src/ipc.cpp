// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipc.h"

/**
 * @brief Created a Unix TCP Socket
 */
int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket() failed");

	return sockfd;
}

/**
 * @brief Created an INET TCP Socket
 */
int create_inet_socket(void)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket() failed");

	return sockfd;
}

/**
 * @brief Connects to UNIX socket
 */
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

/**
 * @brief Connects to INET socket
 */
int connect_inet_socket(int fd)
{
	struct sockaddr_in addr;
	int connectfd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = inet_addr(IP);

	connectfd = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(connectfd < 0, "connect() failed");

	return -1;
}

/**
 * @brief Sends buf of size len to socket
 */
ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	ssize_t rc;
	rc = write(fd, buf, len);
	DIE(rc < 0, "write() failed");

	return rc;
}

/**
 * @brief Receives buf of size len from socket
 */
ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	ssize_t rc;
	rc = read(fd, buf, len);
	DIE(rc < 0, "recv() failed");

	return rc;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	int rc;

	rc = close(fd);
	DIE(rc < 0, "close() failed");

	// unlink(SOCKET_NAME);
}
