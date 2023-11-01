#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "db.h"
#include "ssl.h"

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd;  /* server <-> worker bidirectional notification channel */
  int server_eof;
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  int msg_count = get_msg_count();
  struct api_msg *msg = malloc(sizeof(struct api_msg) + 512);

  if(get_msg(&state->api,msg,msg_count-1) == 0) {
    api_send(&state->api,msg);
  }

  api_send_free(msg);
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
static int notify_workers(struct worker_state *state) {
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

void handle_send_all_msg( struct worker_state *state ) {

  int msg_count = get_msg_count();

  struct api_msg *msg = malloc(sizeof(struct api_msg) + 512);

  int i;
  for (i = 0; i < msg_count; i++) {
    if(get_msg(&state->api,msg,i) == 0) {
      api_send(&state->api,msg);
    }
  }

  api_send_free(msg);
}

int handle_no_permission( struct worker_state *state, const struct api_msg *msg ) {
  struct api_msg *res_msg = NULL;

  static const char *MSG_ERROR = "error: command not currently available";

  size_t arg1_size = ((strlen(MSG_ERROR)+1)*sizeof(char));
  size_t arg2_size = 0;
  res_msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  res_msg->arg_1_size = arg1_size;
  res_msg->arg_2_size = arg2_size;

  res_msg->command = CMD_INVALID;

  memcpy(res_msg->payload,MSG_ERROR,arg1_size);

  api_send(&state->api,res_msg);
  api_send_free(res_msg);

  return 0;
}


int handle_register( struct worker_state *state, const struct api_msg *msg) {

  int res = 0;
  struct api_msg *res_msg = NULL;
  struct api_state *api = &state->api;
  char *res_body;

  if (api->logged_in) {
    handle_no_permission(state,msg);
    return 0;
  }

  char *username = malloc(msg->arg_1_size);
  char *password = malloc(msg->arg_2_size);
  
  strcpy(username,msg->payload);
  strcpy(password,msg->payload + msg->arg_1_size);

  res = create_user(username,password);

  static const char *MSG_SUCCESS = "registration succeeded";
  static const char *MSG_INVALID_PWD = "error: length of password invalid";
  static const char *MSG_INVALID_USER = "error: length of username invalid";
  static const char *MSG_CHAR_NOT_ALLOWED = "error: character not allowed!";


  switch(res) {
    case 0:
      res_body = malloc(sizeof(char) * strlen(MSG_SUCCESS));
      strcpy(res_body, MSG_SUCCESS);

      api->logged_in = 1;
      strcpy(api->user,username);
      break;
    case -1:
      res_body = malloc(sizeof(char) * (28 + strlen(username)));
      strcpy(res_body, "error: user ");
      strcpy(res_body + 12, username);
      strcpy(res_body + 12 + strlen(username), " already exists");
      break;
    case -2:
      res_body = malloc(sizeof(char) * strlen(MSG_INVALID_USER));
      strcpy(res_body, MSG_INVALID_USER);
      break;
    case -3:
      res_body = malloc(sizeof(char) * strlen(MSG_INVALID_PWD));
      strcpy(res_body, MSG_INVALID_PWD);
      break;
    case -4:
      res_body = malloc(sizeof(char) * strlen(MSG_CHAR_NOT_ALLOWED));
      strcpy(res_body, MSG_CHAR_NOT_ALLOWED);
      break;
  }

  size_t arg1_size = (strlen(res_body)+1)*sizeof(char);
  size_t arg2_size = (strlen(username)+1)*sizeof(char);
  res_msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  res_msg->arg_1_size = arg1_size;
  res_msg->arg_2_size = arg2_size;

  res_msg->command = CMD_REGISTER;

  memcpy(res_msg->payload,res_body,arg1_size);
  memcpy(res_msg->payload+arg1_size,username,arg2_size);


  api_send(&state->api,res_msg);
  api_send_free(res_msg);

  free(res_body);

  if (res == 0) handle_send_all_msg(state);

  free(username);
  free(password);

  return 0;
}

int handle_login( struct worker_state *state, const struct api_msg *msg ) {
  assert(state);
  assert(msg);

  int res = 0;
  struct api_msg *res_msg = NULL;
  struct api_state *api = &state->api;
  char *res_body;


  if (api->logged_in) {
    handle_no_permission(state,msg);
    return 0;
  }


  char *username = malloc(msg->arg_1_size);
  char *password = malloc(msg->arg_2_size);
  
  strcpy(username,msg->payload);
  strcpy(password,msg->payload + msg->arg_1_size);

  res = login_user(username,password);

  static const char *MSG_CHAR_NOT_ALLOWED = "error: invalid credentials";
  static const char *MSG_ERROR = "error: invalid credentials";
  static const char *MSG_SUCCESS = "authentication succeeded";

  switch(res) {
    case 0:
      res_body = malloc(sizeof(char)+1 * strlen(MSG_SUCCESS));
      strcpy(res_body, MSG_SUCCESS);

      api->logged_in = 1;
      strcpy(api->user,username);
      break;
    case -1:
      res_body = malloc(sizeof(char) * strlen(MSG_ERROR));
      strcpy(res_body, MSG_ERROR);
      break;
    case -2:
      res_body = malloc(sizeof(char) * strlen(MSG_CHAR_NOT_ALLOWED));
      strcpy(res_body, MSG_CHAR_NOT_ALLOWED);
      break;
  }

  size_t arg1_size = (strlen(res_body)+1)*sizeof(char);
  size_t arg2_size = (strlen(username)+1)*sizeof(char);
  res_msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  res_msg->arg_1_size = arg1_size;
  res_msg->arg_2_size = arg2_size;

  res_msg->command = CMD_LOGIN;

  memcpy(res_msg->payload,res_body,arg1_size);
  memcpy(res_msg->payload + arg1_size,api->user,arg2_size);

  api_send(&state->api,res_msg);
  api_send_free(res_msg);

  if (res == 0) handle_send_all_msg(state);

  free(res_body);
  free(username);
  free(password);

  return 0;
}

void handle_logout( struct worker_state *state ) {
  struct api_state *api = &state->api;
  if(api->logged_in) {
    set_user_offline(api->user);
  }
}

int handle_user_dne( struct worker_state *state ) {
  struct api_msg *res_msg = NULL;

  static const char *MSG_ERROR = "error: user not found";

  size_t arg1_size = ((strlen(MSG_ERROR)+1)*sizeof(char));
  size_t arg2_size = 0;
  res_msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  res_msg->arg_1_size = arg1_size;
  res_msg->arg_2_size = arg2_size;

  res_msg->command = CMD_INVALID;

  memcpy(res_msg->payload,MSG_ERROR,arg1_size);

  api_send(&state->api,res_msg);
  api_send_free(res_msg);
  return 0;
}

int handle_users( struct worker_state *state, const struct api_msg *msg ) {
  struct api_msg *res_msg = NULL;

  char *users = all_users();

  size_t arg1_size = ((strlen(users)+1)*sizeof(char));
  size_t arg2_size = 0;
  res_msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  res_msg->arg_1_size = arg1_size;
  res_msg->arg_2_size = arg2_size;

  res_msg->command = CMD_USERS;
  

  memcpy(res_msg->payload,users,arg1_size);


  api_send(&state->api,res_msg);
  api_send_free(res_msg);

  free(users);

  return 0;
}  

int handle_send_pub_message( struct worker_state *state, const struct api_msg *msg ) {
  int res = 0;
  struct api_msg *res_msg = NULL;
  char *res_body;

  res = create_message(&state->api,msg);




  static const char *MSG_CHAR_NOT_ALLOWED = "error: invalid credentials";

  if (res == -1) {
    res_body = malloc(sizeof(char) * strlen(MSG_CHAR_NOT_ALLOWED));
    strcpy(res_body, MSG_CHAR_NOT_ALLOWED);

    size_t arg1_size = (strlen(res_body)+1)*sizeof(char);
    size_t arg2_size = 0;
    res_msg = malloc(
      sizeof(struct api_msg) +
      arg1_size + arg2_size
    );

    res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
    res_msg->arg_1_size = arg1_size;
    res_msg->arg_2_size = arg2_size;

    res_msg->command = CMD_INVALID;

    memcpy(res_msg->payload,res_body,arg1_size);

    api_send(&state->api,res_msg);
    api_send_free(res_msg);
    return -1;
  }

  notify_workers(state);

  return 0;
}

int handle_send_prv_message( struct worker_state *state, const struct api_msg *msg ) {
  int res = 0;
  struct api_msg *res_msg = NULL;
  char *res_body;

  char *username = malloc(msg->arg_1_size);
  strcpy(username,msg->payload);
  if(!user_exists(username)) {
    handle_user_dne(state);
    return -1;
  }

  res = create_message(&state->api,msg);

  static const
   char *MSG_CHAR_NOT_ALLOWED = "error: invalid credentials";

  if (res == -1) {
    res_body = malloc(sizeof(char) * strlen(MSG_CHAR_NOT_ALLOWED));
    strcpy(res_body, MSG_CHAR_NOT_ALLOWED);

    size_t arg1_size = (strlen(res_body)+1)*sizeof(char);
    size_t arg2_size = 0;
    res_msg = malloc(
      sizeof(struct api_msg) +
      arg1_size + arg2_size
    );

    res_msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
    res_msg->arg_1_size = arg1_size;
    res_msg->arg_2_size = arg2_size;

    res_msg->command = CMD_INVALID;

    memcpy(res_msg->payload,res_body,arg1_size);

    api_send(&state->api,res_msg);
    api_send_free(res_msg);
    return -1;
  }

  notify_workers(state);

  return 0;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
  struct worker_state *state,
  const struct api_msg *msg) {
    struct api_state *api = &state->api;

    if(
      (
        msg->command == CMD_PRV_MSG ||
        msg->command == CMD_PUB_MSG ||
        msg->command == CMD_USERS
      ) && api->logged_in == 0
    ) {
      handle_no_permission(state,msg);
      return 0;
    }

    if(msg->command == CMD_REGISTER) {
      handle_register(state,msg);
    } 
    else if(msg->command == CMD_LOGIN) {
      handle_login(state,msg);
    }
    else if(msg->command == CMD_USERS) {
      handle_users(state,msg);
    }
    else if(msg->command == CMD_PUB_MSG) {
      handle_send_pub_message(state,msg);
    }
    else if(msg->command == CMD_PRV_MSG) {
      handle_send_prv_message(state,msg);
    }
    else if(msg->command == CMD_EXIT) {
      state->eof = 1;
    }
    return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  struct api_msg *msg = malloc(sizeof(struct api_msg) + 512);
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, msg);
  if (r < 0) return -1;
  if (r == 0) {
    state->eof = 1;
    return 0;
  }

  /* execute request */
  if (execute_request(state, msg) != 0) {
    success = 0;
  }


  /* clean up state associated with the message */
  api_recv_free(msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->api.ssl)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(
  struct worker_state *state,
  int connfd,
  int server_fd) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
  struct worker_state *state) {

  ssl_free(&state->api);
  api_state_free(&state->api);

  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn))
void worker_start(
  int connfd,
  int server_fd) {
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0) {
    goto cleanup;
  }

  ssl_server_configure(connfd, &state.api, SSL_SERVER_KEY_PATH, SSL_SERVER_CA_CERT_PATH);

  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }
  handle_logout(&state);

cleanup:
  /* cleanup worker */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}
