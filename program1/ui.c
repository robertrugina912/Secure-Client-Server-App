#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "ui.h"
#include "api.h"

int shift_str(char *str, int len, int start) {
    int i;
    for(i = start; i < len; i++) {
      str[i - 1] = str[i];
    }
    len--;
    return len;
}
void trim_str(char *str) {
  int len = strlen(str);


  int leading_spaces = 0;
  int trailing_spaces = 0;
  int i;

  for(i = 0; i < len; i++) {
    if (str[i] != 32 && str[i] != 9) break;
    leading_spaces++;
  }

  for(i = len-1; i >= 0; i--) {
    if (str[i] != 32 && str[i] != 9) break;
    trailing_spaces++;
  }

  for(i = 0; i < leading_spaces; i++) {
    len = shift_str(str,len,1);
  }
  if(trailing_spaces > 0) str[len-trailing_spaces] = '\0';
  else str[len] = '\0';
}
void clean_str(char *str) {

  int len = strlen(str);
  int i;

  for(i = 0; i < len; i++) {
    if (str[i+2] == '\0'){
      break;
    }
    while(
      (str[i] == 32 || str[i] == 9) &&
      (str[i+1] == 32 || str[i+1] == 9)
    ) {
      len = shift_str(str,len,i+1);
    }
  }
  str[len] = '\0';

}


int count_space(char *str) {
  int count = 0;
  int i;
  for (i = 0; i < strlen(str); i++) {
    if (str[i] == 32 || str[i] == 9) count ++;
  }
  return count;
}



void parse_client_input(struct ui_state *state) {
assert(state);

  char *buf = NULL;
  size_t buf_size = 0;
  size_t i = 0;
  int input = EOF;


  while (input) {
    input = getc(stdin);
    if( feof(stdin) ) {
      state->command = CMD_EXIT;
      return;
    }
    if(input == EOF || input == '\n') input = 0;
    if (buf_size <= i) {
      buf_size += sizeof(input);
      buf = realloc(buf,buf_size);
    }
    buf[i++] = input;
  }


  // REMOVE TRAILING AND LEADING SPACES
  trim_str(buf);

  if(strlen(buf) == 0) {
    state->command = CMD_DO_NOTHING;
    return;
  }
  else if(buf[0] != '@' && buf[0] != '/') {
    state->command = CMD_PUB_MSG;

    state->arg1 = realloc(state->arg1,(strlen(buf)+1)*sizeof(char));
    strcpy(state->arg1,buf);
    free(buf);
    return;
  }
  else if(buf[0] == '@') {
    state->command = CMD_PRV_MSG;
    
    char *stripped_cmd = strtok(buf,"@");

    char *msg = malloc(strlen(stripped_cmd));
    strcpy(msg,stripped_cmd);

    char *temp_user = strtok(stripped_cmd," \t");
    char *user = malloc(strlen(temp_user));
    strcpy(user,temp_user);

    int len = strlen(msg);
    int i;
    for (i = 0; i < strlen(user)+1; i++) {
      len = shift_str(msg,len,1);
    }
    msg[len] = '\0';
    trim_str(msg);

    state->arg1 = realloc(state->arg1,(strlen(user)+1)*sizeof(char));
    state->arg2 = realloc(state->arg2,(strlen(msg)+1)*sizeof(char));

    strcpy(state->arg1,user);
    strcpy(state->arg2,msg);

    free(user);
    free(msg);
    free(buf);
    return;
  }
  

  clean_str(buf);

  int space_count = count_space(buf);

  char *arg_buf = strtok(buf," \t");

  char *arg[3];
  i = 0;
  while (arg_buf != NULL && i < 3) {
    arg[i++] = arg_buf;
    arg_buf = strtok (NULL, " \t");
  }

  if(strcmp(buf,"/help") == 0) {
    state->command = CMD_HELP;
  }
  else if(strcmp(buf,"/exit") == 0) {
    state->command = CMD_EXIT;
  }
  else if(strcmp(buf,"/users") == 0) {
    if (space_count > 0) {
      printf("error: invalid command format\n");
      state->command = CMD_DO_NOTHING;
    }
    state->command = CMD_USERS;
  }
  else if(strcmp(arg[0],"/login") == 0) {

    if(space_count != 2 || strcmp(arg[1],"") == 0 || strcmp(arg[2],"") == 0) {
      printf("error: invalid command format\n");
      state->command = CMD_DO_NOTHING;
    } else {
      state->command = CMD_LOGIN;

      state->arg1 = realloc(state->arg1,(strlen(arg[1])+1)*sizeof(char));
      state->arg2 = realloc(state->arg2,(strlen(arg[2])+1)*sizeof(char));

      strcpy(state->arg1,arg[1]);
      strcpy(state->arg2,arg[2]);
    }
  }
  else if(strcmp(arg[0],"/register") == 0) {   
    if(
      space_count != 2 || strcmp(arg[1],"") == 0 || strcmp(arg[2],"") == 0
    ) {
      printf("error: invalid command format\n");
      state->command = CMD_DO_NOTHING;
    } else {
      state->command = CMD_REGISTER;

      state->arg1 = realloc(state->arg1,(strlen(arg[1])+1)*sizeof(char));
      state->arg2 = realloc(state->arg2,(strlen(arg[2])+1)*sizeof(char));

      strcpy(state->arg1,arg[1]);
      strcpy(state->arg2,arg[2]);
    }
  }
  else if(arg[0][0]=='@') {
    memmove(arg[0],arg[0]+1,strlen(arg[0]));
    if(strcmp(arg[0],"") == 0 || strcmp(arg[1],"") == 0) {
      state->command = CMD_INVALID;
    } else {
      state->command = CMD_PRV_MSG;

      state->arg1 = realloc(state->arg1,(strlen(arg[0])+1)*sizeof(char));
      state->arg2 = realloc(state->arg2,(strlen(arg[1])+1)*sizeof(char));

      strcpy(state->arg1,arg[0]);
      strcpy(state->arg2,arg[1]);
    }
  }
  else {
    printf("error: unknown command ");
    printf("%s\n",arg[0]);
    state->command = CMD_INVALID;
  }

  free(buf);
}



void print_message(const struct api_msg *msg) {
    char *args_str = malloc(msg->arg_1_size);
    strcpy(args_str,msg->payload);

    char *content_str = malloc(msg->arg_2_size);
    strcpy(content_str,msg->payload + msg->arg_1_size);

    char *args_buf = strtok(args_str, ":");

    int i = 0;
    char *args[4];
      while (args_buf != NULL) {
        args[i++] = args_buf;
        args_buf = strtok (NULL, ":");
    }

    time_t timestamp = atoi(args[0]);
    char timestamp_buf[80];
    struct tm ts;

    ts = *localtime(&timestamp);
    strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%d %H:%M:%S", &ts);

    if(strcmp(args[1],"PUB") == 0) {
      printf("%s %s: %s\n", timestamp_buf,args[3],content_str);
    }
    else {
      printf("%s %s: @%s %s\n", timestamp_buf,args[3],args[2],content_str);
    }

    free(args_str);
    free(content_str);
}

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);

  free(state->arg1);
  free(state->arg2);
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {
  assert(state);

  state->arg1 = malloc(1*sizeof(char));
  state->arg2 = malloc(1*sizeof(char));
}
