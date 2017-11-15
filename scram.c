/*-
 * Copyright (c) 2017 Joshua Jackson <jjackson@kallisteconsulting.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "base64/base64.h"
#include "hmac_sha1.h"
#include "pkcs5_pbkdf2.h"
#include "scram.h"

#define NONCE_SIZE 18
#define SCRAM_OK 0
#define SCRAM_FAIL 1

static int digit_count(int number) {
    return (1 + floor(log10(abs(number))));
}

static int valid_value_char(unsigned char c) {
    if (c <= 127 && c != '\0' && c != '=' && c != ',') {
        return 1;
    }
    return 0;
}

static int valid_nonce_char(unsigned char c) {
    if (c >= 0x21 && c <= 127 && c != ',') {
        return 1;
    }
    return 0;
}

static const char generate_nonce_char() {
    unsigned char c = arc4random() & 0x7f;
    if (!valid_nonce_char(c)) {
        return generate_nonce_char();
    }
    return c;
}

static char* generate_nonce() {
    char* nonce = malloc(NONCE_SIZE + 1);
    nonce[NONCE_SIZE] = '\0';
    for (int i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = generate_nonce_char();
    }
    return nonce;
}

int scram_client_first(char* username, char **result, char **client_nonce) {
    int len = strlen(username) + NONCE_SIZE + 8;
    char* msg = malloc(len + 1);
    *client_nonce = generate_nonce();
    snprintf(msg, len + 1, "n,,n=%s,r=%s", username, *client_nonce);
    printf("%s\n", msg);
    size_t *out_len;
    *result = (char *)base64_encode((unsigned char*)msg, len, out_len);
    free(msg);
    return SCRAM_OK;
}

int scram_parse_client_first(char *client_first, char **first_char, char **username, char **client_nonce) {
    if (!strlen(client_first)) {
        return SCRAM_FAIL;
    }
    int found_user = 0;
    int found_nonce = 0;
    char *strbegin, *strparts, *token, *buf;
    size_t out_len;
    char *decode_client_first = (char *)base64_decode((unsigned char *)client_first, strlen(client_first), &out_len);
    *first_char = strndup(decode_client_first, 1);
    strbegin = strparts = strdup(decode_client_first);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "n=") == 0) {
            printf("Found username\n");
            found_user = 1;
            int username_len = strlen(token) - 1;
            *username = strdup(token + 2);
        }
        if (strcmp(buf, "r=") == 0) {
            printf("Found nonce\n");
            found_nonce = 1;
            int client_nonce_len = strlen(token) - 1;
            *client_nonce = strdup(token + 2);
        }
        free(buf);
    }
    free(strbegin);
    if (found_user && found_nonce) {
        return SCRAM_OK;
    }
    else {
        return SCRAM_FAIL;
    }
}

int scram_server_first(int user_iteration_count, char *user_salt, char *first_char, char *client_nonce, char **result, char **server_nonce) {
    if (strcmp(first_char, "n") != 0 && strcmp(first_char, "y") != 0 && strcmp(first_char, "p") != 0) {
        *result = strdup("e=other-error");
        return SCRAM_FAIL;
    }
    *server_nonce = generate_nonce();
    printf("client nonce: %s\n", client_nonce);
    printf("server nonce: %s\n", *server_nonce);
    int len = NONCE_SIZE + NONCE_SIZE + strlen(user_salt) + digit_count(user_iteration_count) + 8;
    printf("digits: %d\n", digit_count(user_iteration_count));
    char* msg = malloc(len + 1);
    snprintf(msg, len, "r=%s%s,s=%s,i=%d", client_nonce, *server_nonce, user_salt, user_iteration_count);
    printf("server first len %d: %s\n", len, msg);
    size_t *out_len;
    *result = (char *)base64_encode((unsigned char*)msg, len, out_len);
    printf("server first message: %s\n", *result);
    free(msg);
    return SCRAM_OK;
}

int scram_client_final(char **result) {
    return SCRAM_OK;
}

int scram_server_final(char **result) {
    return SCRAM_OK;
}


