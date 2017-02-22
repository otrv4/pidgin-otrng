#include "otr4-client.h"

otr4_client_t*
otr4_client_new() {
    otr4_client_t *client = malloc(sizeof(otr4_client_t));
    if (!client)
        return NULL;

    otr4_conversation_t *conv = malloc(sizeof(otr4_conversation_t));
    if (!conv)
        return NULL;

    cs_keypair_generate(client->keypair);

    conv->ctx = NULL;
    conv->conn = otrv4_new(client->keypair);
    client->conv = conv;
    return client;
}

void
otr4_client_free(otr4_client_t *client) {
    otrv4_free(client->conv->conn);
    client->conv->conn = NULL;
    free(client->conv);

    client->conv = NULL;
    cs_keypair_destroy(client->keypair);

    free(client);
}

otr4_conversation_t*
get_conversation_with(const char *recipient, otr4_client_t *client) {
    //TODO
    return client->conv;
}

int
otr4_client_send(char **newmessage, const char *message, const char *recipient, otr4_client_t *client) {
    otr4_conversation_t *conv = get_conversation_with(recipient, client);

    if (conv->conn->state == OTRV4_STATE_START) {
        return 1;
    }

    //TODO: add notifications (like "ttried to send a message while not in
    //encrypted")
    *newmessage = NULL;
    if (!otrv4_send_message((unsigned char **) newmessage, (unsigned char*) message, strlen(message)+1, conv->conn)) {
        return -1;
    }

    return 0;
}

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message, const char *recipient, otr4_client_t *client) {
    otrv4_state state_before;
    *newmessage = NULL;
    *todisplay = NULL;

    otr4_conversation_t *conv = get_conversation_with(recipient, client);
    state_before = conv->conn->state;

    otrv4_response_t *response = otrv4_response_new();
    if (!otrv4_receive_message(response, (const string_t) message, strlen(message), conv->conn)) {
      otrv4_response_free(response);
      return 0; //Should this cause the message to be ignored or not?
    }

    if (state_before != OTRV4_STATE_ENCRYPTED_MESSAGES && conv->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES) {
        conv->ctx->msgstate = OTRL_MSGSTATE_ENCRYPTED; //Sync our state with OTR3 state
        if (client->callbacks && client->callbacks->gone_secure)
            client->callbacks->gone_secure(conv);
    }

    if (response->to_send) {
      char *tosend = strdup(response->to_send);
      *newmessage = tosend;
    }

    int should_ignore = 1;
    if (response->to_display) {
	char *plain = strdup(response->to_display);
        *todisplay = plain;
        should_ignore = 0;
    }

    otrv4_response_free(response);
    return should_ignore;
}

char*
otr4_client_query_message(const char *recipient, const char* message, otr4_client_t *client) {
    otr4_conversation_t *conv = get_conversation_with(recipient, client);

    //TODO: implement policy
    char *ret = NULL;
    otrv4_build_query_message(&ret, conv->conn, (const string_t) message, strlen(message));
    return ret;
}

void
otr4_watch_context(ConnContext *ctx, otr4_client_t *client) {
    //TODO: There should be one per conversation (from, to, proto,
    //instance_tag)
    client->conv->ctx = ctx;
}
