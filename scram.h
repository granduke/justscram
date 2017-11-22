#define SCRAM_OK 0
#define SCRAM_FAIL 1


int gen_scram_salted_password(char *password, char *salt_b64, int rounds, unsigned char **result);


/* Client side functions */
int scram_client_first(char *username, char **result, char **client_nonce);
int scram_handle_server_first(char *server_first, char *client_nonce, char **server_first_decoded, char **combined_nonce, char **server_nonce, char **user_salt, int *iteration_count);
int scram_client_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result);
int scram_handle_server_final(char *server_final, char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding);


/* Server side functions */
int scram_handle_client_first(char *client_first, char **username, char **client_nonce);
int scram_server_first(int user_iteration_count, char *user_salt_b64, char *client_nonce, char **result, char **server_first_decoded, char **server_nonce);
int scram_handle_client_final(char *client_final, char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce);
int scram_server_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result);
