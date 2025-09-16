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
#include <wait.h>
#include <ctype.h>

#include "ipc.h"
#include "server.h"
#include "log.h"


#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#ifndef NMAX
#define NMAX 256
#endif

static void sigsegv_handler(int signo)
{
	(void) signo;
	exit(EXIT_FAILURE);
}

static void sigint_handler(int signo)
{
	(void) signo;
	exit(EXIT_SUCCESS);
}

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	int rc;

	rc = dup2(lib->output_fd, STDOUT_FILENO);

	struct sigaction sgn_act;
	memset(&sgn_act, 0, sizeof(sgn_act));
	sgn_act.sa_handler = sigsegv_handler;
	sgn_act.sa_flags = SA_RESTART;
	rc = sigaction(SIGSEGV, &sgn_act, NULL);
	DIE(rc < 0, "sigaction");

	memset(&sgn_act, 0, sizeof(sgn_act));
	sgn_act.sa_handler = sigint_handler;
	sgn_act.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGINT, &sgn_act, NULL);
	DIE(rc < 0, "sigaction");

	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	void *library_handle;
	char log_message[NMAX];
	char *error;

	library_handle = dlopen(lib->libname, RTLD_LAZY);
	error = dlerror();

	if (error) {
		if (strlen(lib->filename)) {
			sprintf(log_message, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		} else {
			if (strlen(lib->funcname))
				sprintf(log_message, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
			else
				sprintf(log_message, "Error: %s run could not be executed.\n", lib->libname);
		}

		write(lib->output_fd, log_message, strlen(log_message));
		dlog(log_message, WARNING);
		return -1;
	}

	lib->handle = library_handle;
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	void *func;
	char *error;
	char log_message[NMAX];

	if (strlen(lib->funcname))
		func = dlsym(lib->handle, lib->funcname);
	else
		func = dlsym(lib->handle, "run");
	
	error = dlerror();

	if (error) {
		if (strlen(lib->filename)) {
			sprintf(log_message, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		} else {
			if (strlen(lib->funcname))
				sprintf(log_message, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
			else
				sprintf(log_message, "Error: %s run could not be executed.\n", lib->libname);
		}

		write(lib->output_fd, log_message, strlen(log_message));
		dlog(log_message, WARNING);
		return -1;
	}

	if (strlen(lib->filename))
		((void (*)(char *))func)(lib->filename);	
	else {
		((void (*)(void))func)();
	}

	dlog("Executed function successfully!\n", INFO);

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	char log_message[NMAX];
	char *error;
	int rc;

	rc = dlclose(lib->handle);
	error = dlerror();

	if (error) {
		if (strlen(lib->filename)) {
			sprintf(log_message, "Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		} else {
			if (strlen(lib->funcname))
				sprintf(log_message, "Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
			else
				sprintf(log_message, "Error: %s run could not be executed.\n", lib->libname);
		}

		write(lib->output_fd, log_message, strlen(log_message));
		sprintf(log_message, "dlclose() failed: %s\n", error);
		dlog(log_message, WARNING);
	}

	return rc;
}

static int lib_posthooks(struct lib *lib)
{
	(void) lib;
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	dlog("Prehooking...\n", INFO);
	err = lib_prehooks(lib);
	if (err)
		return err;

	dlog("Loading library...\n", INFO);
	err = lib_load(lib);
	if (err)
		return err;

	dlog("Executing function...\n", INFO);
	err = lib_execute(lib);
	if (err)
		return err;

	dlog("Closing...\n", INFO);
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

static void help()
{
	printf("The server is run using the following parameters:\n");
	printf("1. \"--inet\" for INET sockets.\n");
	printf("2. \"--help\" for this info.\n");
	printf("3. \"--client_count=x\" where x is the maximum number of clients.\n");
}

static inline int contains_digits(const char *str)
{
	int len = strlen(str);
	for (int i = 0; i < len; ++i) {
		if (!isdigit(str[i]))
			return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	/* TODO: Implement server connection. */
	int ret, pid;
	struct lib lib;
	int listenfd, connectfd;
	int network_socket_flag = 0;
	int n_clients = 100; // to get from argv or from STDIN, set to 100 as default
	char libname[NMAX], filename[NMAX], funcname[NMAX];
	char buffer[NMAX];

	struct sockaddr_in client_address_inet, server_address_inet;
	struct sockaddr_un client_address_unix, server_address_unix;
	socklen_t inet_length = sizeof(client_address_inet), unix_length = sizeof(client_address_unix);

	create_log(SERVER_LOG);

	for (int i = 0; i < argc; ++i) {
		if (!strcmp(argv[i], "--inet")) {
			network_socket_flag = 1;
		} else if (!strcmp(argv[i], "--help")) {
			help();
			return 0;
		} else if (!strncmp(argv[i], "--client_count=", strlen("--client_count="))) {
			if (contains_digits(argv[i] + strlen("--client_count="))) {
				help();
				dlog("Server should be run using --client_count=x, where x is a number", WARNING);
				return -1;
			}
			n_clients = atoi(argv[i] + strlen("--client_count="));
		}
	}

	sprintf(buffer, "Running server with maximum %d connections.\n", n_clients);
	dlog(buffer, INFO);

	memset(&client_address_inet, 0, sizeof(client_address_inet));
	memset(&client_address_unix, 0, sizeof(client_address_unix));
	memset(&server_address_inet, 0, sizeof(server_address_inet));
	memset(&server_address_unix, 0, sizeof(server_address_unix));

	setvbuf(stdout, NULL, 0, 0);

	if (network_socket_flag) {
		dlog("You chose INET sockets!\n", INFO);
		listenfd = create_inet_socket();
		server_address_inet.sin_family = AF_INET;
		server_address_inet.sin_addr.s_addr = inet_addr(IP);
		server_address_inet.sin_port = htons(PORT);

		ret = bind(listenfd, (struct sockaddr *) &server_address_inet, inet_length);
		DIE(ret < 0, "bind");
	} else {
		dlog("You chose UNIX sockets!\n", INFO);
		listenfd = create_socket();
		server_address_unix.sun_family = AF_UNIX;
		snprintf(server_address_unix.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);

		unlink(SOCKET_NAME);
		ret = bind(listenfd, (struct sockaddr *) &server_address_unix, unix_length);
		DIE(ret < 0, "bind");
	}

	dlog("Waiting on connections...\n", INFO);
	ret = listen(listenfd, n_clients);

	while (1) {
		/* TODO - get message from client */

		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		
		memset(&client_address_inet, 0, sizeof(client_address_inet));
		memset(&client_address_unix, 0, sizeof(client_address_unix));
		memset(&inet_length, 0, sizeof(inet_length));
		memset(&unix_length, 0, sizeof(unix_length));
	
		if (network_socket_flag) {
			connectfd = accept(listenfd, (struct sockaddr *) &client_address_inet, &inet_length);
			memset(buffer, 0, sizeof(buffer));
			sprintf(buffer, "Accepted connection from %s:%d\n",
					inet_ntoa(client_address_inet.sin_addr), ntohs(client_address_inet.sin_port));
			dlog(buffer, INFO);
		} else {
			connectfd = accept(listenfd, (struct sockaddr *) &client_address_unix, &unix_length);
		}

		pid = fork();

		switch (pid)
		{
		case -1:
			DIE(1, "Fork failed.\n");
			break;
		case 0:
			memset(filename, 0, sizeof(filename));
			memset(funcname, 0, sizeof(funcname));
			memset(libname, 0, sizeof(libname));
			memset(buffer, 0, sizeof(buffer));

			recv_socket(connectfd, buffer, sizeof(buffer));
			parse_command(buffer, libname, funcname, filename);

			lib.outputfile = strdup(OUTPUT_TEMPLATE);
			lib.output_fd = mkstemp(lib.outputfile);
			lib.libname = libname;
			lib.filename = filename;
			lib.funcname = funcname;

			pid_t pid2;

			pid2 = fork();
			switch (pid2)
			{
			case -1:
				DIE(1, "fork() failed");
				break;
			case 0:
				lib_run(&lib);
				break;
			default:
				waitpid(pid2, NULL, 0);
				send_socket(connectfd, lib.outputfile, strlen(lib.outputfile));
			}
			free(lib.outputfile);
			close(connectfd);
			return 0;
		default:
			close(connectfd);
			break;
		}
	}

	close(connectfd);
	close(listenfd);
	remove_log();
	return 0;
}
