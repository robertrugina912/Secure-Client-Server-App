#include <openssl/ssl.h>
#include "api.h"

#ifndef SSL_H
#define SSL_H

// #define ENABLE_CRYPTO 1

// #define SSL_SERVER_SELF_CERT_PATH        "./serverkeys/server-self-cert.pem"
#define SSL_SERVER_KEY_PATH         "./serverkeys/server-key.pem"
#define SSL_SERVER_CA_KEY_PATH      "./serverkeys/ca-key.pem"
#define SSL_SERVER_CA_CERT_PATH     "./serverkeys/server-ca-cert.pem"
#define SSL_SERVER_CSR_PATH         "./serverkeys/server-csr.pem"

#define SSL_TTP_CA_CERT_PATH        "./ttpkeys/ca-cert.pem"
#define SSL_TTP_SESSION_KEY_PATH    "./ttpkeys/session_key.pem"

#define SSL_EVP_ENCRYPT_FLAG		1
#define SSL_EVP_DECRYPT_FLAG		0

int ssl_block_accept(SSL *ssl, int fd);
int ssl_block_connect(SSL *ssl, int fd);
int ssl_block_read(SSL *ssl, int fd, void *buf, int len);
int ssl_block_write(SSL *ssl, int fd, const void *buf, int len);
int ssl_has_data(SSL *ssl);
int set_nonblock(int fd);

void ssl_server_configure(int fd, struct api_state *state, const char *pathkey, const char *pathcert);
void ssl_client_configure(int fd, struct api_state *state, const char *cacertpath);
void ssl_block_read_check(int res);
void ssl_block_write_check(int res);

int ssl_encrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *plaintext, int plaintext_len);
int ssl_decrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *ciphertext, int ciphertext_len);

void ssl_rand(unsigned char *bytes, int len);
unsigned char *ssl_parsehex(unsigned char *s, size_t len);
size_t ssl_get_max_ciphertext_size(size_t plaintext_size);

void ttp_request_session_key(void);
unsigned char *ttp_get_session_key(void);
void ttp_request_rsa_keys(char name[]);

void ssl_free(struct api_state *state);

int hexchartoraw(const char hexchar, char *outbuff);
size_t hextoraw(const char *hexchar, unsigned char **outbuff);

#endif