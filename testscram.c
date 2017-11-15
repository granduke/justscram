#include <stdio.h>
#include <stdlib.h>

#include "scram.h"

int main() {
    char username[] = "jas";
    int r;
    char *client_first;
    char *client_nonce;
    //
    char *first_char;
    char *parsed_username;
    char *parsed_client_nonce;
    //
    char *server_first;
    char *server_nonce;
    //
    char *parsed_combined_salt;
    char *parsed_user_salt;
    int parsed_iteration_count;
    //
    r = scram_client_first(username, &client_first, &client_nonce);
    printf("client nonce: %s\n", client_nonce);
    printf("client first message: %s", client_first);
    r = scram_parse_client_first(client_first, &first_char, &parsed_username, &parsed_client_nonce);
    printf("first char: %s\n", first_char);
    printf("parsed username: %s\n", parsed_username);
    printf("parsed client nonce: %s\n", parsed_client_nonce);
    scram_server_first(14, "salt", first_char, parsed_client_nonce, &server_first, &server_nonce);
    printf("server first message: %s", server_first);
    scram_parse_server_first(server_first, &parsed_combined_salt, &parsed_user_salt, &parsed_iteration_count);
    printf("parsed combined salt: %s\n", parsed_combined_salt);
    printf("parsed user salt: %s\n", parsed_user_salt);
    printf("parsed iteration count: %d\n", parsed_iteration_count);
    free(client_first);
    free(client_nonce);
    free(server_first);
    free(server_nonce);
    free(first_char);
    free(parsed_username);
    free(parsed_client_nonce);
    free(parsed_combined_salt);
    free(parsed_user_salt);
    return(0);
}
