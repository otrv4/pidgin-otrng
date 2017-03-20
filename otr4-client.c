#include "otr4-client.h"

otr4_client_adapter_t*
otr4_client_adapter_new(otr4_client_callbacks_t *cb) {
    otr4_client_adapter_t *c = malloc(sizeof(otr4_client_adapter_t));
    if (!c)
        return NULL;

    c->real_client = otr4_client_new(NULL);
    c->real_client->callbacks = cb;
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
    list_foreach(client->plugin_conversations, c, {
      otr4_plugin_conversation_t *conv = (otr4_plugin_conversation_t*) c->data;
      if (conv->conv == wanted)
        return conv->ctx;
  });

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
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client) {
    char *ret = malloc(OTR4_FPRINT_HUMAN_LEN);
    if (!ret)
        return NULL;

    uint8_t *our_fp = otr4_client_get_our_fingerprint(client->real_client);
    if (!our_fp)
        return NULL;

    otr4_fingerprint_hash_to_human(ret, our_fp);
    free(our_fp);

    return ret;
}

static int
generate_privkey(otr4_client_adapter_t *client) {
    client->real_client->keypair = malloc(sizeof(cs_keypair_s));
    if (!client->real_client->keypair)
        return -1;

    cs_keypair_generate(client->real_client->keypair);
    return 0;
}

int
otr4_client_adapter_privkey_generate_FILEp(otr4_client_adapter_t *client, FILE *privf) {
    if (!privf)
        return -1;

    if(generate_privkey(client))
        return -2;

    return otr4_privkey_generate_FILEp(client->real_client, privf);
}

int
otr4_client_adapter_read_privkey_FILEp(otr4_client_adapter_t *client, FILE *privf) {
    if (!privf)
        return -1;

    return otr4_read_privkey_FILEp(client->real_client, privf);
}

