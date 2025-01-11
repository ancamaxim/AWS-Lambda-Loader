// SPDX-License-Identifier: BSD-3-Clause

#define _XOPEN_SOURCE 700
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "ipc.h"
#include "server.h"
#include "log.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#ifndef LOG_FILE
#define LOG_FILE "server.log"
#endif

static void sigsegv_handler(int signo)
{
	dlog("You received SIGSEGV. Execution failed, program terminated.", WARNING);

	exit(EXIT_FAILURE);
}

static void sigint_handler(int signo)
{
	dlog("You received SIGINT. Execution interrupted.", WARNING);

	exit(EXIT_SUCCESS);
}

static void sigchld_handler(int signo)
{
	
}

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	int rc;

	lib->outputfile = strdup(OUTPUT_TEMPLATE);
	lib->output_fd = mkstemp(lib->outputfile);
	
	struct sigaction sgn_act;
	memset(&sgn_act, 0, sizeof(sgn_act));
	sgn_act.sa_handler = sigsegv_handler;
	rc = sigaction(SIGSEGV, &sgn_act, NULL);
	DIE(rc < 0, "sigaction");

	memset(&sgn_act, 0, sizeof(sgn_act));
	sgn_act.sa_handler = sigint_handler;
	rc = sigaction(SIGINT, &sgn_act, NULL);
	DIE(rc < 0, "sigaction");

	memset(&sgn_act, 0, sizeof(sgn_act));
	sgn_act.sa_handler = sigchld_handler;
	rc = sigaction(SIGCHLD, &sgn_act, NULL);
	DIE(rc < 0, "sigaction");

	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	void *library_handle;
	char log_message[LOG_LENGTH];
	char *error;

	sprintf(log_message, "Opening library %s...\n", lib->outputfile);
	dlog(log_message, INFO);

	library_handle = dlopen(lib->outputfile, RTLD_LAZY);

	lib->handle = library_handle;

	error = dlerror();

	if (error) {
		if (lib->funcname)
			fprintf(lib->output_fd, "Error: <%s> [<%s>", lib->libname, lib->funcname);
		else
			fprintf(lib->output_fd, "Error: <%s> [<%s>", lib->libname, "run");

		if (lib->filename)
			fprintf(lib->output_fd, " [<%s>]", lib->filename);

		fprintf(lib->output_fd, "] could not be executed.\n");

		sprintf(log_message, "dlopen() failed: %s\n", error);
		dlog(log_message, WARNING);

		return -1;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	void *func;
	char *error;
	char log_message[LOG_LENGTH];

	if (lib->funcname)
		func = dlsym(lib->handle, lib->funcname);
	else
		func = dlsym(lib->handle, "run");
	
	error = dlerror();

	if (error) {
		if (lib->funcname)
			fprintf(lib->output_fd, "Error: <%s> [<%s>", lib->libname, lib->funcname);
		else
			fprintf(lib->output_fd, "Error: <%s> [<%s>", lib->libname, "run");

		if (lib->filename)
			fprintf(lib->output_fd, " [<%s>]", lib->filename);

		fprintf(lib->output_fd, "] could not be executed.\n");

		sprintf(log_message, "dlsym() failed: %s\n", error);
		dlog(log_message, WARNING);

		return -1;
	}

	if (lib->filename)
		((void (*)(char *))func)(lib->filename);
	else
		((void (*)(void))func)();

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret;
	int connectfd, listenfd;
	int network_conn_flag = 0, n_connect = 100;
	struct lib lib;
	
	struct sockaddr_un client_unix, server_unix;
	struct sockaddr_in server_inet, client_inet;

	int inet_length = sizeof(struct sockaddr_in), unix_length = sizeof(struct sockaddr_un);

	memset(&server_unix, 0, unix_length);
	memset(&server_inet, 0, inet_length);
	memset(&client_unix, 0, unix_length);
	memset(&client_inet, 0, inet_length);

	server_unix.sun_family = AF_UNIX;
	snprintf(server_unix.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);

	if (network_conn_flag) {
		listenfd = create_inet_socket();
		server_inet.sin_family = AF_INET;
		server_inet.sin_port = htons(PORT);
		server_inet.sin_addr.s_addr = inet_addr(IP);
		ret = bind(listenfd, (struct sockaddr_in *) &server_inet, inet_length);
		DIE(ret < 0, "bind failed");
	} else {
		listenfd = create_socket();
		server_unix.sun_family = AF_UNIX;
		snprintf(server_unix.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);

		ret = bind(listenfd, (struct sockaddr_in *) &server_unix, unix_length);
		DIE(ret < 0, "bind failed");
	}

	ret = listen(listenfd, n_connect);
	create_log(LOG_FILE);

	while (1) {
		/* TODO - get message from client */
		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		ret = lib_run(&lib);
		
		if (network_conn_flag)
			connectfd = accept(listenfd, (struct sockaddr_in *) &client_inet, inet_length);
		else
			connectfd = accept(listenfd, (struct sockaddr_in *) &client_unix, unix_length)
	}

	return 0;
}
