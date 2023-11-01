#include <stdint.h>
#include <openssl/ssl.h>

#ifndef _API_H_
#define _API_H_

struct __attribute__((__packed__)) api_msg {
  // HEADER
  uint8_t command;
  size_t total_size;
  size_t arg_1_size;
  size_t arg_2_size;

  // DATA
  char payload[];
};

struct api_state {
  int fd;
  SSL *ssl;
  SSL_CTX *ctx;
  
  char *user;
  int logged_in;
};

int api_send(struct api_state *state, struct api_msg *msg);
void api_send_free(struct api_msg *msg);

int api_recv(struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
