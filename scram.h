#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCRAM_H
#define SCRAM_H

#define SCRAM_OK 0
#define SCRAM_FAIL 1
#define SCRAM_CONTINUE 2

#ifdef __linux__ 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#endif

#include "crypto/sha1.h"

typedef struct {
    char *username;
    char *password;
    char *user_salt_b64;
    unsigned char *salted_password;
    char *channel_binding;
    char *client_first;
    char *client_final;
    char *server_first;
    char *server_first_decoded;
    char *server_final;
    char *client_nonce;
    char *server_nonce;
    char *combined_nonce;
    int iteration_count;
    int auth_step;
} scram_state_t;


/* Client side authentication functions */
void scram_client_init(scram_state_t *state, char *username, char *password, char *channel_binding);
int scram_client_auth_first(scram_state_t *state, char **out_message);
int scram_client_auth_step(scram_state_t *state, char *in_message, char **out_message);
void scram_client_state_free(scram_state_t *state);


/* Server side authentication functions */
void scram_server_init(scram_state_t *state, char *channel_binding);
int scram_server_auth_first(scram_state_t *state, char *in_message, char **username);
int scram_server_auth_info(scram_state_t *state, unsigned char *salted_password, char *user_salt_b64, int iteration_count);
int scram_server_auth_step(scram_state_t *state, char *in_message, char **out_message);
void scram_server_state_free(scram_state_t *state);


/* Password hashing */
int gen_scram_salted_password(char *password, char *salt_b64, int rounds, unsigned char **result);


/* Client side low level functions */
int scram_client_first(char *username, char **result, char **client_nonce);
int scram_handle_server_first(char *server_first, char *client_nonce, char **server_first_decoded, char **combined_nonce, char **server_nonce, char **user_salt, int *iteration_count);
int scram_client_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result);
int scram_handle_server_final(char *server_final, char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding);


/* Server side low level functions */
int scram_handle_client_first(char *client_first, char **username, char **client_nonce);
int scram_server_first(int user_iteration_count, char *user_salt_b64, char *client_nonce, char **result, char **server_first_decoded, char **server_nonce);
int scram_handle_client_final(char *client_final, char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce);
int scram_server_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result);

#endif

#ifdef __cplusplus
}
#endif
