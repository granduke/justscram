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
#include "compat/compat.h"
#include "scram.h"


void scram_client_init(char *username, char *salted_password, size_t salted_password_len, char *channel_binding, scram_state_t *state) {
    state->username = strdup(username);
    state->salted_password = malloc(salted_password_len);
    memcpy(state->salted_password, salted_password, salted_password_len);
    state->channel_binding = strdup(channel_binding);
    state->client_first = NULL;
    state->client_final = NULL;
    state->server_first = NULL;
    state->server_first_decoded = NULL;
    state->client_nonce = NULL;
    state->server_nonce = NULL;
    state->combined_nonce = NULL;
    state->user_salt_b64 = NULL;
    state->auth_step = 0;
}

void scram_server_init(char *channel_binding, scram_state_t *state) {
    state->channel_binding = strdup(channel_binding);
    state->username = NULL;
    state->salted_password = NULL;
    state->client_first = NULL;
    state->client_final = NULL;
    state->server_first = NULL;
    state->server_first_decoded = NULL;
    state->client_nonce = NULL;
    state->server_nonce = NULL;
    state->combined_nonce = NULL;
    state->user_salt_b64 = NULL;
    state->auth_step = 0;
}

int scram_client_auth_step(scram_state_t *state, char *in_message, char **out_message) {
    int r;
    if (state->auth_step == 0) {
        r = scram_client_first(state->username, &(state->client_first), &(state->client_nonce));
        if (r == SCRAM_OK) {
            state->auth_step++;
            *out_message = strdup(state->client_first);
            return SCRAM_CONTINUE;
        }
    }
    else if (state->auth_step == 1) {
        r = scram_handle_server_first(in_message, state->client_nonce, &(state->server_first_decoded), &(state->combined_nonce), &(state->server_nonce), &(state->user_salt_b64), &(state->iteration_count));
        if (r == SCRAM_OK) {
            r = scram_client_final(state->server_first_decoded, state->username, state->salted_password, state->client_nonce, state->server_nonce, state->channel_binding, &(state->client_final));
            if (r == SCRAM_OK) {
                state->auth_step++;
                *out_message = strdup(state->client_final);
                return SCRAM_CONTINUE;
            }
        }
    }
    else if (state->auth_step == 2) {
        r = scram_handle_server_final(in_message, state->server_first_decoded, state->username, state->salted_password, state->client_nonce, state->server_nonce, state->channel_binding);
        if (r == SCRAM_OK) {
            state->auth_step++;
            return SCRAM_OK;
        }
    }
    return SCRAM_FAIL;
}

int scram_server_auth_first(scram_state_t *state, char *in_message, char **username) {
    int r;
    if (state->auth_step == 0) {
        r = scram_handle_client_first(in_message, &(state->username), &(state->client_nonce));
        if (r == SCRAM_OK) {
            state->auth_step = 1;
            *username = strdup(state->username);
            return SCRAM_CONTINUE;
        }
    }
    return SCRAM_FAIL;
}

int scram_server_auth_info(scram_state_t *state, char *salted_password, size_t salted_password_len, char *user_salt_b64) {
    if (state->auth_step == 1) {
        memcpy(state->salted_password, salted_password, salted_password_len);
        state->user_salt_b64 = strdup(user_salt_b64);
        state->auth_step = 2;
        return SCRAM_CONTINUE;
    }
    return SCRAM_FAIL;
}

int scram_server_auth_step(scram_state_t *state, char *in_message, char **out_message) {
    int r;
    if (state->auth_step == 2) {
        r = scram_server_first(state->iteration_count, state->user_salt_b64, state->client_nonce, &(state->server_first), &(state->server_first_decoded), &(state->server_nonce));
        if (r == SCRAM_OK) {
            state->auth_step++;
            *out_message = strdup(state->server_first);
            return SCRAM_CONTINUE;
        }
    }
    else if (state->auth_step == 3) {
        r = scram_handle_client_final(state->client_final, state->server_first_decoded, state->username, state->salted_password, state->client_nonce, state->server_nonce);
        if (r == SCRAM_OK) {
            r = scram_server_final(state->server_first_decoded, state->username, state->salted_password, state->client_nonce, state->server_nonce, state->channel_binding, &(state->server_final));
            if (r == SCRAM_OK) {
                state->auth_step++;
                *out_message = strdup(state->server_final);
                return SCRAM_OK;
            }
        }
    }
    return SCRAM_FAIL;
}

void scram_state_free(scram_state_t *state) {
    if (state->username) {
        free(state->username);
    }
    if (state->salted_password) {
        free(state->salted_password);
    }
    if (state->channel_binding) {
        free(state->channel_binding);
    }
    if (state->client_first) {
        free(state->client_first);
    }
    if (state->client_final) {
        free(state->client_final);
    }
    if (state->server_first) {
        free(state->server_first);
    }
    if (state->server_first_decoded) {
        free(state->server_first_decoded);
    }
    if (state->server_final) {
        free(state->server_final);
    }
    if (state->client_nonce) {
        free(state->client_nonce);
    }
    if (state->server_nonce) {
        free(state->server_nonce);
    }
    if (state->combined_nonce) {
        free(state->combined_nonce);
    }
    if (state->user_salt_b64) {
        free(state->user_salt_b64);
    }
}
