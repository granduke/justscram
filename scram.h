#define SCRAM_OK 0
#define SCRAM_FAIL 1


int gen_scram_salted_password(char *password, char *salt, int rounds, unsigned char **result);


/* Client side functions */
int scram_client_first(char *username, char **result, char **client_nonce);
int scram_handle_server_first(char *server_first, char *client_nonce, char **combined_nonce, char **server_nonce, char **user_salt, int *iteration_count);
int scram_client_final(char *server_first, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result);


/* Server side functions */
int scram_handle_client_first(char *client_first, char **first_char, char **username, char **client_nonce);
int scram_server_first(int user_iteration_count, char *user_salt, char *first_char, char *client_nonce, char **result, char **server_nonce);
int scram_server_final(char **result);
