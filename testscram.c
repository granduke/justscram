#include <stdio.h>
#include <stdlib.h>

#include "scram.h"

int main() {
    char username[] = "jas";
    char *result;
    char *client_nonce;
    scram_client_first(username, &result, &client_nonce);
    printf("client nonce: %s\n", client_nonce);
    printf("client first message: %s", result);
    free(result);
    free(client_nonce);
    return(0);
}
