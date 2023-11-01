#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "ssl.h"

struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;

};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
  const char *hostname, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  return fd;
}

static void help() {
  printf("\nAvailable commands:\n");
  printf("%-44s %s","/exit","Exits chat client\n");
  printf("%-44s %s","/users","View all users\n");
  printf("%-44s %s","/login [username] [password]","Login client\n");
  printf("%-44s %s","/register [username] [password]","Register client\n");
  printf("%-44s %s","@[username] [message]","Send message to user\n");
  printf("%-44s %s","[message]","Send global message\n\n");
}

static int client_process_command(struct client_state *state) {
  assert(state);
  parse_client_input(&state->ui);
  //parse_client_input(&state->ui);
  struct ui_state *ui = &state->ui;
  struct api_msg *msg = NULL;

  switch(ui->command) {
    case CMD_EXIT:
      state->eof = 1;
      break;
      //return 0;
    case CMD_HELP:
      help();
      return 0;
    case CMD_INVALID:
      return 0;
    case CMD_DO_NOTHING:
      return 0;
  }

  size_t arg1_size = ((strlen(ui->arg1)+1)*sizeof(char));
  size_t arg2_size = ((strlen(ui->arg2)+1)*sizeof(char));

#ifdef ENABLE_CRYPTO
  if (ui->command == CMD_PRV_MSG) {

    unsigned char *iv, *ciphertext;
    unsigned char *key = ttp_get_session_key();

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    unsigned char *iv_raw = malloc(iv_len * sizeof(unsigned char*));
    memcpy(iv_raw, "0", 2);
    iv = ssl_parsehex(iv_raw, iv_len);

    ciphertext = malloc(ssl_get_max_ciphertext_size(arg2_size) * sizeof(unsigned char));
    int ciphertext_len = ssl_encrypt(key, iv, ciphertext, (unsigned char*) ui->arg2, (int) arg2_size);

    char *hex_cyphertext = malloc(ciphertext_len * 2 * sizeof(char));
    char hex[2];
    char *hex_format = "%.2x";
    int offset = 0;

    for(int i = 0; i < ciphertext_len; i++) {
      sprintf(hex,hex_format,ciphertext[i]);
      strcpy(hex_cyphertext + offset,hex);
      offset += strlen(hex);
    }

    arg2_size = (size_t) strlen(hex_cyphertext) + 1;
    ui->arg2 = realloc(ui->arg2, (arg2_size) * sizeof(char));
    memcpy(ui->arg2,(char*) hex_cyphertext, arg2_size);
  }
#endif
  
  msg = malloc(
    sizeof(struct api_msg) +
    arg1_size + arg2_size
  );

  msg->total_size = sizeof(struct api_msg) + arg1_size + arg2_size;
  msg->arg_1_size = arg1_size;
  msg->arg_2_size = arg2_size;

  msg->command = ui->command;

  memcpy(msg->payload,ui->arg1,arg1_size);
  memcpy(msg->payload + arg1_size, ui->arg2, arg2_size);

  api_send(&state->api,msg);
  api_send_free(msg);

  return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
  struct client_state *state,
  const struct api_msg *msg) {
  

  struct api_state *api = &state->api;
  
  if (
      msg->command == CMD_REGISTER || 
      msg->command == CMD_LOGIN    || 
      msg->command == CMD_INVALID  || 
      msg->command == CMD_USERS
  ) {
    if (strcmp(msg->payload, "registration succeeded") == 0) {
      strcpy(api->user,msg->payload + msg->arg_1_size);
      ttp_request_rsa_keys(api->user);
      api->logged_in = 1;
    }
    if (strcmp(msg->payload, "authentication succeeded") == 0) {
      strcpy(api->user,msg->payload + msg->arg_1_size);
      api->logged_in = 1;
    }

    printf("%s\n",msg->payload);
  }
  else if(msg->command == CMD_PRV_MSG) {
#ifdef ENABLE_CRYPTO
    unsigned char *iv, *plaintext;
    unsigned char *key = ttp_get_session_key();

    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    unsigned char *iv_raw = malloc(iv_len * sizeof(unsigned char*));
    memcpy(iv_raw, "0", 1);
    iv = ssl_parsehex(iv_raw, iv_len);

    plaintext = malloc(msg->arg_2_size * sizeof(unsigned char));
#endif

    struct api_msg *msg_copy = malloc(msg->total_size);
    memcpy(msg_copy, msg, msg->total_size); 
#ifdef ENABLE_CRYPTO
    char *hex_payload = (char*) malloc((msg->arg_2_size+1) * sizeof(char));
    memcpy(hex_payload,msg->payload + msg->arg_1_size,msg->arg_2_size);

    size_t ciphertext_len = (msg->arg_2_size / 2);
    unsigned char ciphertext[ciphertext_len];

    int i;
    int offset = 0;
    int cipher_offset = 0;
    char hex[2];
    unsigned char *out = malloc(1);

    for (i = 0; i < ciphertext_len; i++) {
      hex[0] = hex_payload[offset];
      hex[1] = hex_payload[offset+1];

      hextoraw(hex,&out);
      ciphertext[i] = out[0];

      offset += 2;
      cipher_offset++;
    } 
    ciphertext[16] = '\0';

    int plaintext_len = ssl_decrypt(key, iv, plaintext, ciphertext, ciphertext_len);

    memcpy(msg_copy->payload + msg_copy->arg_1_size, (char*) plaintext, plaintext_len);
    msg_copy->arg_2_size = (size_t) plaintext_len;
#endif
    print_message(msg_copy);
  }
  else if(msg->command == CMD_PUB_MSG) {
    print_message(msg);
  }

  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
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

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->api.ssl)) {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  return 0;
}

static void client_state_free(struct client_state *state) {
  ssl_free(&state->api);
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);
}

static void usage(void) {
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}


int main(int argc, char **argv) {


  int fd;
  uint16_t port;
  struct client_state state;

  /* check arguments */
  if (argc != 3) usage();
  if (parse_port(argv[2], &port) != 0) usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0) return 1;


  /* initialize API */
  api_state_init(&state.api, fd);

  ssl_client_configure(state.api.fd, &state.api, SSL_TTP_CA_CERT_PATH);

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  /* clean up */
  client_state_free(&state);
  close(fd);

  return 0;
}
