#include "otr4-client.h"

otr4_client_t*
otr4_client_new() {
    otr4_client_t *client = malloc(sizeof(otr4_client_t));
    if (!client)
        return NULL;

    cs_keypair_generate(client->keypair);
    client->connection = otrv4_new(client->keypair);
    return client;
}

void
otr4_client_free(otr4_client_t *client) {
    otrv4_free(client->connection);
    client->connection = NULL;

    cs_keypair_destroy(client->keypair);

    free(client);
}

otrv4_t*
get_connection_for_recipient(const char *recipient, otr4_client_t *client) {
    //TODO
    return client->connection;
}

int
otr4_client_send(char **newmessage, const char *message, const char *recipient, otr4_client_t *client) {
    otrv4_t *conn = get_connection_for_recipient(recipient, client);

    if (conn->state == OTRV4_STATE_START) {
        return 1;
    }

    //TODO: add notifications (like "ttried to send a message while not in
    //encrypted")
    *newmessage = NULL;
    if (!otrv4_send_message((unsigned char **) newmessage, (unsigned char*) message, strlen(message)+1, conn)) {
        return -1;
    }

    return 0;
}

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message, const char *recipient, otr4_client_t *client) {
    *newmessage = NULL;
    *todisplay = NULL;

    otrv4_t *conn = get_connection_for_recipient(recipient, client);

    //TODO: add notifications
    otrv4_response_t *response = otrv4_response_new();
    if (!otrv4_receive_message(response, (const string_t) message, strlen(message), conn)) {
      otrv4_response_free(response);
      return 0; //Should this cause the message to be ignored or not?
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
    otrv4_t *conn = get_connection_for_recipient(recipient, client);

    //TODO: implement policy
    char *ret = NULL;
    otrv4_build_query_message(&ret, conn, (const string_t) message, strlen(message));
    return ret;
}
