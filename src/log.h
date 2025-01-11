#ifndef _LOG_H
#define _LOG_H

#define SERVER_LOG "server.log"

enum log_t {
    WARNING,
    DEBUG,
    INFO
};

void dlog(char *message, enum log_t log);
void create_log(char *filename);
void remove_log(void);

#endif