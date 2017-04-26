#include "otr4-client.h"

otr4_client_adapter_t*
otr4_client_adapter_new(otrv4_callbacks_t *callbacks) {
    otr4_client_adapter_t *c = malloc(sizeof(otr4_client_adapter_t));
    if (!c)
        return NULL;

    c->real_client = otr4_client_new(NULL);
    c->real_client->callbacks = callbacks;
    c->plugin_conversations = NULL;

    return c;
}

void
otr4_client_adapter_free(otr4_client_adapter_t *client) {
    list_free_full(client->plugin_conversations);
    client->plugin_conversations = NULL;
    client->real_client->callbacks = NULL;
    free(client);
}

char*
otr4_client_adapter_query_message(const char *recipient,
                          const char* message,
                          otr4_client_adapter_t *client) {
    return otr4_client_query_message(recipient, message, client->real_client);
}

int
otr4_client_adapter_send(char **newmessage,
                 const char *message,
                 const char *recipient,
                 otr4_client_adapter_t *client) {
    return otr4_client_send(newmessage, message, recipient, client->real_client);
}

int
otr4_client_adapter_receive(char **newmessage,
                    char **todisplay,
                    const char *message,
                    const char *recipient,
                    otr4_client_adapter_t *client) {
    return otr4_client_receive(newmessage, todisplay, message, recipient, client->real_client);
}

ConnContext*
otr4_client_adapter_get_context(const otr4_conversation_t *wanted, otr4_client_adapter_t *client) {
    list_element_t *el = NULL;
    for (el = client->plugin_conversations; el; el = el->next) {
        otr4_plugin_conversation_t *conv = (otr4_plugin_conversation_t*) el->data;
        if (conv->conv == wanted)
            return conv->ctx;
    }

    return NULL;
}

void
otr4_client_adapter_set_context(const char* recipient, ConnContext *ctx, otr4_client_adapter_t *client) {
    otr4_conversation_t *conv = otr4_client_get_conversation(1, recipient, client->real_client);
    if(otr4_client_adapter_get_context(conv, client)) {
        return;
    }

    otr4_plugin_conversation_t *plugin_conv = malloc(sizeof(otr4_plugin_conversation_t));
    if (!plugin_conv)
        return;

    plugin_conv->conv = conv;
    plugin_conv->ctx = ctx;
    client->plugin_conversations = list_add(plugin_conv, client->plugin_conversations);
}

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client)
{
    char *ret = NULL;

    otrv4_fingerprint_t our_fp = {0};
    if (otr4_client_get_our_fingerprint(our_fp, client->real_client))
        return NULL;

    ret = malloc(OTR4_FPRINT_HUMAN_LEN);
    if (!ret)
        return NULL;

    otr4_fingerprint_hash_to_human(ret, our_fp);
    return ret;
}

int
otr4_client_generate_privkey(otr4_client_adapter_t *client) {
    client->real_client->keypair = malloc(sizeof(otrv4_keypair_t));
    if (!client->real_client->keypair)
        return -1;

    uint8_t sym[ED448_PRIVATE_BYTES];
    gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);

    otrv4_keypair_generate(client->real_client->keypair, sym);
    return 0;
}

int
otr4_client_adapter_privkey_generate_FILEp(otr4_client_adapter_t *client, FILE *privf) {
    if (!privf)
        return -1;

    if(otr4_client_generate_privkey(client))
        return -2;

    return otr4_privkey_generate_FILEp(client->real_client, privf);
}

int
otr4_client_adapter_read_privkey_FILEp(otr4_client_adapter_t *client, FILE *privf) {
    if (!privf)
        return -1;

    return otr4_read_privkey_FILEp(client->real_client, privf);
}

const otr4_conversation_t *
otr4_client_adapter_get_conversation_from_connection(const otrv4_t *wanted, const otr4_client_adapter_t *client) {
    if (!wanted)
        return NULL;

    list_element_t *el = NULL;
    for (el = client->plugin_conversations; el; el = el->next) {
        otr4_plugin_conversation_t *conv = (otr4_plugin_conversation_t*) el->data;
        if (!conv->conv)
            continue;

        if (conv->conv->conn == wanted)
            return conv->conv;
    }

    return NULL;
}

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client)
{
    return otr4_client_disconnect(newmessage, recipient, client->real_client);
}



void otr4_account_free(otr4_account_t *account)
{
    free(account->account);
    account->account = NULL;

    free(account->protocol);
    account->account = NULL;

    free(account);
}
