#include <stdint.h>
#include "api.h"

#ifndef _UI_H_
#define _UI_H_

#define CMD_EXIT 0
#define CMD_LOGIN 1
#define CMD_PRV_MSG 2
#define CMD_PUB_MSG 3
#define CMD_REGISTER 4
#define CMD_USERS 5
#define CMD_HELP 6
#define CMD_INVALID 7
#define CMD_DO_NOTHING 8

struct ui_state {
  uint8_t command;
  char *arg1;
  char *arg2;
};

//void parse_client_input(struct ui_state *state);

void parse_client_input(struct ui_state *state);

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);
void print_message(const struct api_msg *msg);

/* TODO add UI calls interact with user on stdin/stdout */

#endif /* defined(_UI_H_) */
