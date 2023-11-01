#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <fcntl.h>

#include "ssl.h"
#include "api.h"

int ssl_encrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len) {
  int ciphertext_len;

  const EVP_CIPHER *type = EVP_aes_128_cbc();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx) 
    fprintf(stderr, "Error while creating a context.\n");
  
  if (EVP_CipherInit(ctx, type, key, iv, SSL_EVP_ENCRYPT_FLAG) != 1)
    fprintf(stderr, "Error while initializing a cipher.\n");

  if (EVP_CipherUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1)
    fprintf(stderr, "Error while updating a cipher.\n");

  if (EVP_CipherFinal(ctx, ciphertext, &ciphertext_len) != 1)
    fprintf(stderr, "Error while finalizing decryption\n");
  
  EVP_CIPHER_CTX_free(ctx);
  free(key);
  free(iv);
  return ciphertext_len;
}

int ssl_decrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *ciphertext, int ciphertext_len) 
{
  int plaintext_len;

  const EVP_CIPHER *type = EVP_aes_128_cbc();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx) 
    fprintf(stderr, "Error while creating a context.\n");

  if (EVP_CipherInit(ctx, type, key, iv, SSL_EVP_DECRYPT_FLAG) != 1)
    fprintf(stderr, "Error while initializing a cipher.\n");

  if (EVP_CipherUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) != 1)
    fprintf(stderr, "Error while updating a cipher.\n");

  if (EVP_CipherFinal(ctx, plaintext, &plaintext_len) != 1)
    fprintf(stderr, "Error while finalizing decryption\n");

  EVP_CIPHER_CTX_free(ctx);
  free(key);
  free(iv);
  return plaintext_len;
}

size_t ssl_get_max_ciphertext_size(size_t plaintext_size) {
  return ((plaintext_size + 16) / 16) * 16;
}

void ssl_server_configure(int fd, struct api_state *state, const char *pathkey, const char *pathcert) {
  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL *ssl = SSL_new(ctx);
  if (!SSL_use_certificate_file(ssl, pathcert, SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Something went wrong with cert\n");
      exit(1);
  };

  if (!SSL_use_PrivateKey_file(ssl, pathkey, SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Something went wrong with key\n");
      exit(1);
  }

  /* set up SSL connection with client */
  set_nonblock(fd);
  SSL_set_fd(ssl, fd);
  ssl_block_accept(ssl, fd);

  state->ssl = (SSL*) malloc(sizeof(ssl));
  state->ssl = ssl;
  state->ctx = ctx;
}

void ssl_client_configure(int fd, struct api_state *state, const char *cacertpath) {
  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_load_verify_locations(ctx, cacertpath, NULL);
  SSL *ssl = SSL_new(ctx);
  SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

  /* configure the socket as non-blocking */
  set_nonblock(fd);

  /* set up SSL connection with client */
  SSL_set_fd(ssl, fd);

  if (ssl_block_connect(ssl, fd) != 1) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "verify result=%ld\n", SSL_get_verify_result(ssl));
    exit(1);
  }

  state->ssl = (SSL*) malloc(sizeof(ssl));
  state->ssl = ssl;
}


void ttp_request_rsa_keys(char *name) {
  char script[] = "./rsa_keypair_gen.sh ";
  strcat(script, name);
  system(script);
}

void ttp_request_session_key(void) {
  system("./session_key_file_gen.sh");

  const EVP_CIPHER *cipher_type = EVP_aes_128_cbc();
  int key_len = EVP_CIPHER_key_length(cipher_type);

  unsigned char *raw_key = malloc(key_len * sizeof(unsigned char));
  ssl_rand(raw_key, key_len);
  unsigned char *key = ssl_parsehex(raw_key, key_len);

  FILE *file = fopen(SSL_TTP_SESSION_KEY_PATH, "w+");
  fwrite(key, 1, key_len, file);
  fclose(file);
}

unsigned char *ttp_get_session_key(void) {
  const EVP_CIPHER *cipher_type = EVP_aes_128_cbc();
  int key_len = EVP_CIPHER_key_length(cipher_type);

  unsigned char *key = malloc(key_len * sizeof(unsigned char));

  FILE *file = fopen(SSL_TTP_SESSION_KEY_PATH, "r+");
  fread(key, 1, key_len, file);
  fclose(file);

  return key;
}

unsigned char *ssl_parsehex(unsigned char *s, size_t len) {
  unsigned char *buf = calloc(len, 1);
  for (int i = 0; s[i]; i++)
    buf[i/2] |= (s[i]%16 + (s[i]>>6)*9) << 4*(1-i%2);
  return buf;
}

void ssl_rand(unsigned char *buf, int len) {
  for (int i = 0; i < len; i++) {
    RAND_bytes(buf + i, 1);
  }
}

void ssl_free(struct api_state *state) {
  SSL_free(state->ssl);
  SSL_CTX_free(state->ctx);
}

void ssl_block_read_check(int res) {
    switch (res) {
        case 0: {
            perror("SSL socket was closed.\n");
            break;
        }
        case -1: {
            perror("Error occurred on SSL socket\n");
            break;
        }
    }
}

void ssl_block_write_check(int res) {
    switch (res) {
        case 0: {
            perror("SSL socket was closed.\n");
            break;
        }
        case -1: {
            perror("Error occurred on SSL socket\n");
            break;
        }
    }  
}

static int ssl_block_if_needed(SSL *ssl, int fd, int r) {
  int err, want_read;
  fd_set readfds, writefds;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *    1: more data available
   */

  /* do we need more input/output? */
  err = SSL_get_error(ssl, r);
  switch (err) {
  case SSL_ERROR_ZERO_RETURN: return 0;
  case SSL_ERROR_WANT_READ:   want_read = 1; break;
  case SSL_ERROR_WANT_WRITE:  want_read = 0; break;
  default:
    if (err == SSL_ERROR_SYSCALL && !ERR_peek_error()) return 0;

    fprintf(stderr, "SSL call failed, err=%d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* wait for more input/output */
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_SET(fd, want_read ? &readfds : &writefds);
  r = select(fd+1, &readfds, &writefds, NULL, NULL);
  if (r != 1) return -1;

  return 1;
}

int ssl_block_accept(SSL *ssl, int fd) {
  int r;

  /* return value:
   *   -1: error
   *    1: success
   */

  /* block until the call succeeds */
  for (;;) {
    r = SSL_accept(ssl);
    if (r == 1) return 1;
    r = ssl_block_if_needed(ssl, fd, r);
    if (r != 1) return -1;
  }
}

int ssl_block_connect(SSL *ssl, int fd) {
  int r;

  /* return value:
   *   -1: error
   *    1: success
   */

  /* block until the call succeeds */
  for (;;) {
    r = SSL_connect(ssl);
    if (r == 1) return 1;
    r = ssl_block_if_needed(ssl, fd, r);
    if (r != 1) return -1;
  }
}

int ssl_block_read(SSL *ssl, int fd, void *buf, int len) {
  char *p = buf, *pend = p + len;
  int r;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *   >0: number of bytes read
   */

  /* we may need to do multiple reads in case one returns prematurely */
  while (p < pend) {
    /* attempt to read */
    r = SSL_read(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }

    /* do we need to block? */
    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }

  return p - (char *) buf;
}

int ssl_block_write(SSL *ssl, int fd, const void *buf, int len) {
  const char *p = buf, *pend = p + len;
  int r;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *   >0: number of bytes written
   */

  /* we may need to do multiple writes in case one returns prematurely */
  while (p < pend) {
    /* attempt to write */
    r = SSL_write(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }
    
    /* do we need to block? */
    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }

  return p - (char *) buf;
}

int ssl_has_data(SSL *ssl) {
  char byte;
  int r;

  /* return value:
   *   0: nothing available
   *   1: data, end-of-file, or error available
   */

  /* verify that at least one byte of user data is available */
  r = SSL_peek(ssl, &byte, sizeof(byte));
  return r > 0 || SSL_get_error(ssl, r) != SSL_ERROR_WANT_READ;
}

int set_nonblock(int fd) {
  int flags, r;

  /* return value:
   *   -1: error
   *    0: success
   */

  /* set O_NONBLOCK flag on given file descriptor */
  flags = fcntl(fd, F_GETFL);
  if (flags == -1) return -1;
  r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (r == -1) return -1;
  return 0;
}

/* Hex conversion function, idea taken from different sources*/
int hexchartoraw(const char hexchar, char *outbuff) {
	if (outbuff == NULL) return 0;

	if (hexchar >= '0' && hexchar <= '9') {
		*outbuff = hexchar - '0';
	} else if (hexchar >= 'A' && hexchar <= 'F') {
		*outbuff = hexchar - 'A' + 10;
	} else if (hexchar >= 'a' && hexchar <= 'f') {
		*outbuff = hexchar - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

/* Hex conversion function, idea taken from different sources*/
size_t hextoraw(const char *hexchar, unsigned char **outbuff) {
	size_t len, i;
	char   b1, b2;

	if (hexchar == NULL || *hexchar == '\0' || outbuff == NULL) return 0;

	len = strlen(hexchar);
	if (len % 2 != 0) return 0;
	len /= 2;

	*outbuff = malloc(len);
	memset(*outbuff, 'A', len);
	for (i=0; i<len; i++) {
		if (!hexchartoraw(hexchar[i*2], &b1) || !hexchartoraw(hexchar[i*2+1], &b2)) return 0;
		(*outbuff)[i] = (b1 << 4) | b2;
	}

	return len;
}
