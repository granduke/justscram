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
    r = scram_client_first(username, &client_first, &client_nonce);
    printf("client nonce: %s\n", client_nonce);
    printf("client first message: %s", client_first);
    r = scram_parse_client_first(client_first, &first_char, &parsed_username, &parsed_client_nonce);
    printf("first char: %s\n", first_char);
    printf("parsed username: %s\n", parsed_username);
    printf("parsed client nonce: %s\n", parsed_client_nonce);
    free(client_first);
    free(client_nonce);
    return(0);
}
