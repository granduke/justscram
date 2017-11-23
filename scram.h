#include <stdlib.h>

#define SCRAM_OK 0
#define SCRAM_FAIL 1
#define SCRAM_CONTINUE 2


typedef struct {
    char *username;
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


/* Client side functions */

void scram_client_init(char *username, char *salted_password, size_t salted_password_len, char *channel_binding, scram_state_t *state);
int scram_client_auth_step(scram_state_t *state, char *in_message, char **out_message);


/* Server side functions */

void scram_server_init(char *channel_binding, scram_state_t *state);
int scram_server_auth_first(scram_state_t *state, char *in_message, char **username);
int scram_server_auth_info(scram_state_t *state, char *salted_password, size_t salted_password_len, char *user_salt_b64);
int scram_server_auth_step(scram_state_t *state, char *in_message, char **out_message);


/* Both sides functions */
int gen_scram_salted_password(char *password, char *salt_b64, int rounds, unsigned char **result);
void scram_state_free(scram_state_t *state);


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
