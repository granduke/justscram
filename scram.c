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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "base64/base64.h"
#include "crypto/hmac_sha1.h"
#include "crypto/pkcs5_pbkdf2.h"
#include "scram.h"

#define NONCE_SIZE 18

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
    char *msg;
    *client_nonce = generate_nonce();
    asprintf(&msg, "n,,n=%s,r=%s", username, *client_nonce);
    printf("%s\n", msg);
    size_t out_len;
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    free(msg);
    return SCRAM_OK;
}

int scram_parse_client_first(char *client_first, char **first_char, char **username, char **client_nonce) {
    if (!strlen(client_first)) {
        return SCRAM_FAIL;
    }
    int found_user = 0, found_nonce = 0;
    char *strbegin, *strparts, *token, *buf;
    size_t out_len;
    char *decode_client_first = (char *)base64_decode((unsigned char *)client_first, strlen(client_first), &out_len);
    *first_char = strndup(decode_client_first, 1);
    strbegin = strparts = strdup(decode_client_first);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "n=") == 0) {
            printf("Found username\n");
            if (found_user) {
                return SCRAM_FAIL;
            }
            else {
                found_user = 1;
                *username = strdup(token + 2);
            }
        }
        if (strcmp(buf, "r=") == 0) {
            printf("Found nonce\n");
            if (found_nonce) {
                return SCRAM_FAIL;
            }
            else {
                found_nonce = 1;
                *client_nonce = strdup(token + 2);
            }
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
    char* msg;
    asprintf(&msg, "r=%s%s,s=%s,i=%d", client_nonce, *server_nonce, user_salt, user_iteration_count);
    printf("server first: %s\n", msg);
    size_t out_len;
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    free(msg);
    return SCRAM_OK;
}

int scram_parse_server_first(char *server_first, char **combined_salt, char **user_salt, int *iteration_count) {
    int found_combined_salt = 0, found_user_salt = 0, found_iteration_count = 0;
    char *strbegin, *strparts, *token, *buf;
    size_t out_len;
    char *decode_server_first = (char *)base64_decode((unsigned char *)server_first, strlen(server_first), &out_len);
    strbegin = strparts = strdup(decode_server_first);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "r=") == 0) {
            printf("Found combined_salt\n");
            if (found_combined_salt) {
                return SCRAM_FAIL;
            }
            else {
                found_combined_salt = 1;
                *combined_salt = strdup(token + 2);
            }
        }
        if (strcmp(buf, "s=") == 0) {
            printf("Found user_salt\n");
            if (found_user_salt) {
                return SCRAM_FAIL;
            }
            else {
                found_user_salt = 1;
                *user_salt = strdup(token + 2);
            }
        }
        if (strcmp(buf, "i=") == 0) {
            printf("Found iteration_count\n");
            if (found_iteration_count) {
                return SCRAM_FAIL;
            }
            else {
                found_iteration_count = 1;
                *iteration_count = (int)strtol(token + 2, (char **)NULL, 10);
            }
        }
        free(buf);
    }
    free(strbegin);
    if (found_combined_salt && found_user_salt && found_iteration_count) {
        return SCRAM_OK;
    }
    else {
        return SCRAM_FAIL;
    }
}

int gen_scram_salted_password(char *password, char *salt, int rounds, unsigned char **result) {
    *result = malloc(20);
    pkcs5_pbkdf2(password, strlen(password), salt, strlen(salt), *result, 20, rounds);
    return SCRAM_OK;
}

void nxor(const unsigned char *a, const unsigned char *b, unsigned char *out, size_t n) {
    for (int i = 0; i < n; i++) {
        out[i] = a[i] & b[i];
    }
}

int scram_client_final(char *server_first, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result) {
    size_t out_len;
    char *channel_binding_encoded;
    char *client_message_for_proof;
    char *auth_message;
    char *client_proof_encoded;
    char *msg;
    uint8_t client_key[20];
    uint8_t stored_key[20];
    uint8_t client_sig[20];
    uint8_t client_proof[20];
    SHA1_CTX ctx;
    channel_binding_encoded = (char *)base64_encode((unsigned char*) channel_binding, strlen(channel_binding), &out_len);
    asprintf(&client_message_for_proof, "c=%s,r=%s%s", channel_binding_encoded, client_nonce, server_nonce);
    hmac_sha1((unsigned char *)"Client Key", 10, scram_salted_password, 20, client_key);
    SHA1Init(&ctx);
    SHA1Update(&ctx, (const uint8_t *)client_key, 20);
    SHA1Final(stored_key, &ctx);
    asprintf(&auth_message, "n=%s,r=%s,%s,%s", username, client_nonce, server_first, client_message_for_proof);
    hmac_sha1((unsigned char *)auth_message, strlen(auth_message), stored_key, 20, client_sig);
    nxor(client_key, client_sig, client_proof, 20);
    client_proof_encoded = (char *)base64_encode((unsigned char*) client_proof, 20, &out_len);
    asprintf(&msg, "%s,p=%s", client_message_for_proof, client_proof_encoded);
    printf("client final: %s\n", msg);
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    return SCRAM_OK;
}

int scram_server_final(char **result) {
    return SCRAM_OK;
}

