int scram_client_first(char *username, char **result, char **client_nonce);
int scram_parse_client_first(char *client_first, char **first_char, char **username, char **client_nonce);
int scram_server_first(int user_iteration_count, char *user_salt, char *first_char, char *client_nonce, char **result, char **server_nonce);
int scram_client_final(char **result);
int scram_server_final(char **result);
