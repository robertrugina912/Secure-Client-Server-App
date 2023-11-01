#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include "api.h"
#include "ssl.h"

int api_send(struct api_state *state, struct api_msg *msg) {
  // int res = send(state->fd, msg, msg->total_size, 0);
  int res = ssl_block_write(state->ssl, state->fd, msg, msg->total_size);
  ssl_block_write_check(res);
  return 0;
}
void api_send_free(struct api_msg *msg) {
  assert(msg);

  free(msg);
  msg = NULL;
}

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {
  assert(state);
  assert(msg);

  int res;

  uint8_t command = 0;

  size_t total_size = 0;
  size_t arg_1_size = 0;
  size_t arg_2_size = 0;

  res = ssl_block_read(state->ssl, state->fd, &command, 1);
  if (res <= 0) return res;
  ssl_block_read_check(res);

  res = ssl_block_read(state->ssl, state->fd, &total_size, 8);
  if (res <= 0) return res;
  ssl_block_read_check(res);
  
  res = ssl_block_read(state->ssl, state->fd, &arg_1_size, 8);
  if (res <= 0) return res;
  ssl_block_read_check(res);

  res = ssl_block_read(state->ssl, state->fd, &arg_2_size, 8);
  if (res <= 0) return res;
  ssl_block_read_check(res);

  msg = realloc(msg, total_size);

  msg->command = command;
  msg->total_size = total_size;
  msg->arg_1_size = arg_1_size;
  msg->arg_2_size = arg_2_size;

  res = ssl_block_read(state->ssl, state->fd, &msg->payload, arg_1_size + arg_2_size);
  if (res <= 0) return res;
  ssl_block_read_check(res);

  return 1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {
  assert(msg);

  if (msg != NULL) {
    free(msg);
  }
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {
  assert(state);

  free(state->user);
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {
  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;
  state->logged_in = 0;
  state->user = malloc(256);
}
