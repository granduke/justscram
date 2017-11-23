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
#include <stdarg.h>

#include "compat/compat.h"
#include "base64/base64.h"
#include "crypto/hmac_sha1.h"
#include "crypto/pkcs5_pbkdf2.h"
#include "scram.h"

#define NONCE_SIZE 18


void debug_printf(const char * fmt, ...) {
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
#endif
}

void debug_hex_print(void *data, size_t len) {
    int i;
    unsigned char *p = (unsigned char *)data;
    for (i = 0; i < len; i++) {
        debug_printf("%02x", p[i]);
    }
    debug_printf("\n");
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
#ifdef DEBUG_STATIC_VALUES
    *client_nonce = strdup("fyko+d2lbbFgONRv9qkxdawL");
#else
    *client_nonce = generate_nonce();
#endif
    asprintf(&msg, "n,,n=%s,r=%s", username, *client_nonce);
    debug_printf("client first %s\n", msg);
    size_t out_len;
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    freezero(msg, out_len);
    return SCRAM_OK;
}

int scram_handle_client_first(char *client_first, char **username, char **client_nonce) {
    if (!strlen(client_first)) {
        return SCRAM_FAIL;
    }
    int found_user = 0, found_nonce = 0;
    char *strbegin, *strparts, *token, *buf;
    size_t client_first_decoded_len;
    char *client_first_decoded = (char *)base64_decode((unsigned char *)client_first, strlen(client_first), &client_first_decoded_len);
    debug_printf("got client first: %s\n", client_first_decoded);
    char *first_char = strndup(client_first_decoded, 1);
    strbegin = strparts = strdup(client_first_decoded);
    freezero(client_first_decoded, client_first_decoded_len);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "n=") == 0) {
            debug_printf("Found username\n");
            if (found_user) {
                free(*username);
            }
            found_user = 1;
            *username = strdup(token + 2);
        }
        if (strcmp(buf, "r=") == 0) {
            debug_printf("Found nonce\n");
            if (found_nonce) {
                freezero(*client_nonce, NONCE_SIZE);
            }
            found_nonce = 1;
            *client_nonce = strdup(token + 2);
        }
        freezero(buf, 2);
    }
    freezero(strbegin, client_first_decoded_len);
    if (strcmp(first_char, "n") != 0 && strcmp(first_char, "y") != 0 && strcmp(first_char, "p") != 0) {
        return SCRAM_FAIL;
    }

    if (found_user && found_nonce) {
        return SCRAM_OK;
    }
    else {
        return SCRAM_FAIL;
    }
}

int scram_server_first(int user_iteration_count, char *user_salt_b64, char *client_nonce, char **result, char **server_first_decoded, char **server_nonce) {
#ifdef DEBUG_STATIC_VALUES
    *server_nonce = strdup("3rfcNHYJY1ZVvWVs7j");
#else
    *server_nonce = generate_nonce();
#endif
    debug_printf("client nonce: %s\n", client_nonce);
    debug_printf("server nonce: %s\n", *server_nonce);
    asprintf(server_first_decoded, "r=%s%s,s=%s,i=%d", client_nonce, *server_nonce, user_salt_b64, user_iteration_count);
    debug_printf("server first: %s\n", *server_first_decoded);
    size_t out_len;
    *result = (char *)base64_encode((unsigned char*)*server_first_decoded, strlen(*server_first_decoded), &out_len);
    return SCRAM_OK;
}

int scram_handle_server_first(char *server_first, char *client_nonce, char **server_first_decoded, char **combined_nonce, char **server_nonce, char **user_salt, int *iteration_count) {
    int found_combined_nonce = 0, found_user_salt = 0, found_iteration_count = 0;
    char *strbegin, *strparts, *token, *buf;
    size_t server_first_decoded_len;
    *server_first_decoded = (char *)base64_decode((unsigned char *)server_first, strlen(server_first), &server_first_decoded_len);
    strbegin = strparts = strdup(*server_first_decoded);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "r=") == 0) {
            debug_printf("Found combined nonce\n");
            if (found_combined_nonce) {
                freezero(*combined_nonce, strlen(*combined_nonce));
            }
            found_combined_nonce = 1;
            *combined_nonce = strdup(token + 2);
            *server_nonce = strdup(token + 2 + strlen(client_nonce));
        }
        if (strcmp(buf, "s=") == 0) {
            if (found_user_salt) {
                freezero(*user_salt, strlen(*user_salt));
            }
            found_user_salt = 1;
            *user_salt = strdup(token + 2);
            debug_printf("Found user salt %s\n", *user_salt);
        }
        if (strcmp(buf, "i=") == 0) {
            debug_printf("Found iteration count\n");
            if (found_iteration_count) {
                return SCRAM_FAIL;
            }
            else {
                found_iteration_count = 1;
                *iteration_count = (int)strtol(token + 2, (char **)NULL, 10);
            }
        }
        freezero(buf, 2);
    }
    freezero(strbegin, server_first_decoded_len);
    if (found_combined_nonce && found_user_salt && found_iteration_count) {
        return SCRAM_OK;
    }
    else {
        return SCRAM_FAIL;
    }
}

int gen_scram_salted_password(char *password, char *salt_b64, int rounds, unsigned char **result) {
    size_t salt_len;
    char *salt = (char *)base64_decode((unsigned char *)salt_b64, strlen(salt_b64), &salt_len);
    /* SaltedPassword  := Hi(Normalize(password), salt, i) */
    *result = malloc(20);
    pkcs5_pbkdf2(password, strlen(password), salt, salt_len, *result, 20, rounds);
    freezero(salt, salt_len);
    return SCRAM_OK;
}

void nxor(const unsigned char *a, const unsigned char *b, unsigned char **out, size_t n) {
    unsigned char *p;
    for (int i = 0; i < n; i++) {
        p = *out + i;
        *p = a[i] ^ b[i];
    }
}

int timing_safe_compare(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char result = 0;
    for (int i = 0; i < n; i++) {
        result |= a[i] ^ b[i];
    }
    return result;
}

int gen_auth_message(char *server_first, char *username, char *client_nonce, char *server_nonce, char *channel_binding_encoded, char **auth_message) {
    /* AuthMessage := client-first-message-bare + "," + server-first-message + "," + channel-binding "," nonce ["," extensions] */
    /* client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions] */
    /* nonce = "r=" c-nonce [s-nonce] */
    /* username = "n=" saslname */
    asprintf(auth_message, "n=%s,r=%s,%s,c=%s,r=%s%s", username, client_nonce, server_first, channel_binding_encoded, client_nonce, server_nonce);
    debug_printf("\n\nclient first message bare n=%s,r=%s\n", username, client_nonce);
    debug_printf("server first: %s\n", server_first);
    debug_printf("client final message without proof c=%s,r=%s%s\n", channel_binding_encoded, client_nonce, server_nonce);
    debug_printf("auth message %s\n\n\n", *auth_message);
    return SCRAM_OK;
}

int scram_calculate_client_proof(char *server_first, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding_encoded, unsigned char **client_proof) {
    debug_printf("Salted password: ");
    debug_hex_print(scram_salted_password, 20);
    size_t out_len;
    char *auth_message;
    uint8_t client_key[20];
    uint8_t stored_key[20];
    uint8_t client_sig[20];
    SHA1_CTX ctx;
    /* ClientKey := HMAC(SaltedPassword, "Client Key") */
    hmac_sha1((unsigned char *)"Client Key", 10, scram_salted_password, 20, client_key);
    debug_printf("client key: ");
    debug_hex_print(client_key, 20);
    /* StoredKey := H(ClientKey) */
    SHA1Init(&ctx);
    SHA1Update(&ctx, (const uint8_t *)client_key, 20);
    SHA1Final(stored_key, &ctx);
    debug_printf("stored key: ");
    debug_hex_print(stored_key, 20);
    /* ClientSignature := HMAC(StoredKey, AuthMessage) */
    gen_auth_message(server_first, username, client_nonce, server_nonce, channel_binding_encoded, &auth_message);
    hmac_sha1((unsigned char *)auth_message, strlen(auth_message), stored_key, 20, client_sig);
    debug_printf("client sig: ");
    debug_hex_print(client_sig, 20);
    freezero(auth_message, strlen(auth_message));
    *client_proof = malloc(20);
    /* ClientProof := ClientKey XOR ClientSignature */
    nxor(client_key, client_sig, client_proof, 20);
    debug_printf("Client proof: ");
    debug_hex_print(*client_proof, 20);
    return SCRAM_OK;
}

int scram_calculate_server_signature(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding_encoded, unsigned char **server_signature) {
    debug_printf("Salted password: ");
    debug_hex_print(scram_salted_password, 20);
    char *auth_message;
    uint8_t server_key[20];
    gen_auth_message(server_first_decoded, username, client_nonce, server_nonce, channel_binding_encoded, &auth_message);
    /* ServerKey := HMAC(SaltedPassword, "Server Key") */
    hmac_sha1((unsigned char *)"Server Key", 10, scram_salted_password, 20, server_key);
    debug_printf("Server key: ");
    debug_hex_print(server_key, 20);
    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
    *server_signature = malloc(20);
    hmac_sha1((unsigned char *)auth_message, strlen(auth_message), server_key, 20, *server_signature);
    debug_printf("Server signature ");
    debug_hex_print(*server_signature, 20);
    freezero(auth_message, strlen(auth_message));
    return SCRAM_OK;
}

int scram_client_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result) {
    char *client_proof_encoded;
    size_t client_proof_encoded_len;
    char *msg;
    unsigned char *client_proof;
    /* channel-binding = "c=" base64 */
    size_t channel_binding_encoded_len;
    char *channel_binding_encoded = (char *)base64_encode((unsigned char*) channel_binding, strlen(channel_binding), &channel_binding_encoded_len);
    scram_calculate_client_proof(server_first_decoded, username, scram_salted_password, client_nonce, server_nonce, channel_binding_encoded, &client_proof);
    client_proof_encoded = (char *)base64_encode((unsigned char*) client_proof, 20, &client_proof_encoded_len);
    /* client-final-message = channel-binding "," nonce ["," extensions] "," proof */
    /* nonce = "r=" c-nonce [s-nonce] */
    /* proof = "p=" base64 */
    asprintf(&msg, "c=%s,r=%s%s,p=%s", channel_binding_encoded, client_nonce, server_nonce, client_proof_encoded);
    freezero(client_proof, 20);
    freezero(client_proof_encoded, client_proof_encoded_len);
    freezero(channel_binding_encoded, channel_binding_encoded_len);
    debug_printf("client final: %s\n", msg);
    size_t out_len;
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    return SCRAM_OK;
}

int scram_handle_client_final(char *client_final, char *server_first, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce) {
    size_t out_len;
    char *client_final_decoded = (char *)base64_decode((unsigned char *)client_final, strlen(client_final), &out_len);
    debug_printf("got client final: %s\n", client_final_decoded);
    char *strbegin, *strparts, *token, *buf;
    int found_channel_binding = 0, found_combined_nonce = 0, found_client_proof = 0;
    char *client_proof_encoded;
    char *channel_binding_encoded;
    char *combined_nonce;
    char *client_message_bare;
    char *client_proof;
    unsigned char *server_client_proof = malloc(20);
    size_t client_proof_len;
    int proof_differences = 0;
    strbegin = strparts = strdup(client_final_decoded);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "c=") == 0) {
            debug_printf("Found channel binding\n");
            if (found_channel_binding) {
                freezero(channel_binding_encoded, strlen(channel_binding_encoded));
            }
            found_channel_binding = 1;
            channel_binding_encoded = strdup(token + 2);
        }
        if (strcmp(buf, "r=") == 0) {
            debug_printf("Found combined nonce\n");
            if (found_combined_nonce) {
                freezero(combined_nonce, strlen(combined_nonce));
            }
            found_combined_nonce = 1;
            combined_nonce = strdup(token + 2);
        }
        if (strcmp(buf, "p=") == 0) {
            debug_printf("Found client proof\n");
            if (found_client_proof) {
                freezero(client_proof_encoded, strlen(client_proof_encoded));
            }
            found_client_proof = 1;
            client_proof_encoded = strdup(token + 2);
            client_proof = (char *)base64_decode((unsigned char *)client_proof_encoded, strlen(client_proof_encoded), &client_proof_len);
            freezero(client_proof_encoded, strlen(client_proof_encoded));
        }
        freezero(buf, 2);
    }
    freezero(strbegin, strlen(strbegin));
    if (!found_channel_binding || !found_combined_nonce || !found_client_proof || client_proof_len != 20) {
        if (found_channel_binding) {
            freezero(channel_binding_encoded, strlen(channel_binding_encoded));
        }
        if (found_combined_nonce) {
            freezero(combined_nonce, strlen(combined_nonce));
        }
        if (found_client_proof) {
            freezero(client_proof, client_proof_len);
        }
        return SCRAM_FAIL;
    }
    else {
        scram_calculate_client_proof(server_first, username, scram_salted_password, client_nonce, server_nonce, channel_binding_encoded, &server_client_proof);
        proof_differences = timing_safe_compare((unsigned char *)client_proof, (unsigned char *)server_client_proof, 20);
        freezero(channel_binding_encoded, strlen(channel_binding_encoded));
        freezero(combined_nonce, strlen(combined_nonce));
        freezero(client_proof, client_proof_len);
        if (!proof_differences) {
            return SCRAM_OK;
        }
        else {
            return SCRAM_FAIL;
        }
    }
}

int scram_server_final(char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding, char **result) {
    size_t channel_binding_encoded_len;
    char *msg;
    size_t out_len;
    unsigned char *server_signature;
    char *server_signature_encoded;
    size_t server_signature_encoded_len;
    char *channel_binding_encoded = (char *)base64_encode((unsigned char*) channel_binding, strlen(channel_binding), &channel_binding_encoded_len);
    scram_calculate_server_signature(server_first_decoded, username, scram_salted_password, client_nonce, server_nonce, channel_binding_encoded, &server_signature);
    freezero(channel_binding_encoded, channel_binding_encoded_len);
    server_signature_encoded = (char *)base64_encode((unsigned char*)server_signature, 20, &server_signature_encoded_len);
    freezero(server_signature, 20);
    asprintf(&msg, "v=%s", server_signature_encoded);
    freezero(server_signature_encoded, server_signature_encoded_len);
    debug_printf("server final %s\n", msg);
    *result = (char *)base64_encode((unsigned char*)msg, strlen(msg), &out_len);
    freezero(msg, strlen(msg));
    return SCRAM_OK;
}

int scram_handle_server_final(char *server_final, char *server_first_decoded, char *username, unsigned char *scram_salted_password, char *client_nonce, char *server_nonce, char *channel_binding) {
    size_t channel_binding_encoded_len;
    unsigned char *calc_server_signature = malloc(20);
    char *server_signature_encoded;
    char *server_signature;
    size_t server_signature_len;
    int found_server_signature = 0;
    char *channel_binding_encoded = (char *)base64_encode((unsigned char*) channel_binding, strlen(channel_binding), &channel_binding_encoded_len);
    scram_calculate_server_signature(server_first_decoded, username, scram_salted_password, client_nonce, server_nonce, channel_binding_encoded, &calc_server_signature);
    freezero(channel_binding_encoded, channel_binding_encoded_len);
    size_t out_len;
    char *decode_server_final = (char *)base64_decode((unsigned char *)server_final, strlen(server_final), &out_len);
    char *strbegin, *strparts, *token, *buf;
    int signature_differences;
    strbegin = strparts = strdup(decode_server_final);
    while ((token = strsep(&strparts, ",")) != NULL) {
        buf = strndup(token, 2);
        if (strcmp(buf, "v=") == 0) {
            debug_printf("Found server signature\n");
            if (found_server_signature) {
                freezero(server_signature_encoded, strlen(server_signature_encoded));
            }
            found_server_signature = 1;
            server_signature_encoded = strdup(token + 2);
            server_signature = (char *)base64_decode((unsigned char *)server_signature_encoded, strlen(server_signature_encoded), &server_signature_len);
            freezero(server_signature_encoded, strlen(server_signature_encoded));
        }
    }
    freezero(strbegin, strlen(strbegin));
    if (found_server_signature) {
        if (server_signature_len != 20) {
            freezero(server_signature, server_signature_len);
            return SCRAM_FAIL;
        }
        else {
            signature_differences = timing_safe_compare((unsigned char *)server_signature, (unsigned char *)calc_server_signature, 20);
            freezero(server_signature, server_signature_len);
            if (signature_differences) {
                return SCRAM_FAIL;
            }
            else {
                return SCRAM_OK;
            }
        }
    }
    else {
        return SCRAM_FAIL;
    }
}
