#ifndef _WORKER_H_
#define _WORKER_H_


#define CMD_EXIT 0
#define CMD_LOGIN 1
#define CMD_PRV_MSG 2
#define CMD_PUB_MSG 3
#define CMD_REGISTER 4
#define CMD_USERS 5
#define CMD_HELP 6
#define CMD_INVALID 7
#define CMD_DO_NOTHING 8

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

#endif /* !defined(_WORKER_H_) */
