#include <stdio.h>
#include <stdlib.h>

#include "scram.h"

int main() {
    char username[] = "jas";
    char password[] = "secret";
    char usersalt[] = "user_salt_text";
    int iterations = 4096;
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
    char *parsed_combined_nonce;
    char *parsed_server_nonce;
    char *parsed_user_salt;
    int parsed_iteration_count;
    //
    unsigned char *salted_password;
    char *client_final;
    //
    r = scram_client_first(username, &client_first, &client_nonce);
    printf("client nonce: %s\n", client_nonce);
    printf("client first message: %s\n", client_first);
    r = scram_handle_client_first(client_first, &first_char, &parsed_username, &parsed_client_nonce);
    printf("first char: %s\n", first_char);
    printf("parsed username: %s\n", parsed_username);
    printf("parsed client nonce: %s\n", parsed_client_nonce);
    r = scram_server_first(iterations, usersalt, first_char, parsed_client_nonce, &server_first, &server_nonce);
    printf("server first message: %s\n", server_first);
    r = scram_handle_server_first(server_first, client_nonce, &parsed_combined_nonce, &parsed_server_nonce, &parsed_user_salt, &parsed_iteration_count);
    printf("parsed server nonce: %s\n", parsed_server_nonce);
    printf("parsed combined nonce: %s\n", parsed_combined_nonce);
    printf("parsed user salt: %s\n", parsed_user_salt);
    printf("parsed iteration count: %d\n", parsed_iteration_count);
    gen_scram_salted_password(password, parsed_user_salt, parsed_iteration_count, &salted_password);
    r = scram_client_final(server_first, username, salted_password, client_nonce, parsed_server_nonce, "n,,", &client_final);
    printf("client final message: %s\n", client_final);
    r = scram_handle_client_final(client_final, server_first, username, salted_password, client_nonce, server_nonce);
    if (r == SCRAM_OK) {
        printf("Server determines authentication SUCCESS\n");
    }
    else {
        printf("Server determines authentication FAILURE\n");
    }
    free(client_first);
    free(client_nonce);
    free(server_first);
    free(server_nonce);
    free(first_char);
    free(parsed_username);
    free(parsed_client_nonce);
    free(parsed_combined_nonce);
    free(parsed_user_salt);
    return(0);
}
