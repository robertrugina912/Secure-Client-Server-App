#include <stdint.h>
#include <sqlite3.h>

#include "api.h"

#ifndef _DB_H_
#define _DB_H_

int set_user_online(char *username);
int set_user_offline(char *username);

int user_exists(char *username);
int create_user(char *username, char *password);
int login_user(char *username, char *password);

char* all_users();

int create_message(struct api_state *api, const struct api_msg *msg);
int get_msg_count(void);
int get_msg(struct api_state *api, struct api_msg *msg, int index);

int db_init(void);

#endif