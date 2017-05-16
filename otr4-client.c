#include "otr4-client.h"

static const otrv4_plugin_callbacks_t *callback_v4 = NULL;
static GHashTable *client_table = NULL;

void otr4_callbacks_set(const otrv4_plugin_callbacks_t *cb) {
    callback_v4 = cb;
}

static gboolean
find_otr_client(gpointer key, gpointer value, gpointer user_data)
{
    const otrv4_t *conn = user_data;
    otr4_client_adapter_t *client = value;

    if (otr4_client_adapter_get_conversation_from_connection(conn, client))
        return true;

    return false;
}

static otr4_client_adapter_t*
otr4_connection_to_client(const otrv4_t *conn)
{
    return g_hash_table_find(client_table, find_otr_client, (gpointer) conn);
}

static otr4_client_conversation_t* conn_to_conv(const otrv4_t *conn)
{
    otr4_client_conversation_t *client_conv = NULL;
    const otr4_client_adapter_t *client = NULL;
    const otr4_conversation_t *conv = NULL;

    client_conv = malloc(sizeof(otr4_client_conversation_t));
    if (!client_conv)
        return NULL;

    client = otr4_connection_to_client(conn);
    conv = otr4_client_adapter_get_conversation_from_connection(conn, client);

    client_conv->account = client->account;
    client_conv->protocol = client->protocol;
    client_conv->peer = conv->recipient;
    //uint16_t their_instance_tag;
    //uint16_t our_instance_tag;

    return client_conv;
}

static void otr4_gone_secure_cb(const otrv4_t *conn)
{
    if (!callback_v4 || !callback_v4->gone_secure)
        return;

    otr4_client_conversation_t* client_conv = conn_to_conv(conn);
    callback_v4->gone_secure(client_conv);
    free(client_conv);
}

static void otr4_gone_insecure_cb(const otrv4_t *conn)
{
    if (!callback_v4 || !callback_v4->gone_insecure)
        return;

    otr4_client_conversation_t* client_conv = conn_to_conv(conn);
    callback_v4->gone_insecure(client_conv);
    free(client_conv);
}

static void otr4_confirm_fingerprint_cb(const otrv4_fingerprint_t fp, const otrv4_t *conn)
{
    if (!callback_v4 || !callback_v4->fingerprint_seen)
        return;

    otr4_client_conversation_t* client_conv = conn_to_conv(conn);
    callback_v4->fingerprint_seen(fp, client_conv);
    free(client_conv);
}

//This will forward libotr callbacks (they only know about otrv4 connections)
//to plugin callbacks (they know about having multiple accounts in mutiple
//protocols and so on)
static otrv4_callbacks_t otr4_callbacks = {
    otr4_gone_secure_cb,
    otr4_gone_insecure_cb,
    otr4_confirm_fingerprint_cb,
};

static void g_destroy_conversation(gpointer data)
{
    otr4_client_adapter_t *client = data;
    otr4_client_adapter_free(client);
}

void
otrv4_userstate_create(void) {
    client_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                         g_destroy_conversation);
}

void otrv4_userstate_destroy(void) {
    g_hash_table_remove_all(client_table);
    client_table = NULL;
}

//NOTE: Key is owned by the hash table.
otr4_client_adapter_t*
otr4_client_from_key(char *key)
{
    otr4_client_adapter_t* client = g_hash_table_lookup(client_table, key);
    if (client)
        return client;

    client = otr4_client_adapter_new(&otr4_callbacks);
    if (!client)
        return NULL;

    g_hash_table_insert(client_table, key, client);
    return client;
}

otr4_client_adapter_t*
otr4_client(const char *accountname, const char *protocol)
{
    otr4_client_adapter_t *ret = NULL;
    char *key = NULL;

    asprintf(&key, "%s:%s", protocol, accountname);
    if (!key)
        return NULL;

    ret = otr4_client_from_key(key);
    if (!ret)
        return NULL;

    ret->account = g_strdup(accountname);
    ret->protocol = g_strdup(protocol);

    return ret;
}

void
otr4_privkey_read_FILEp(FILE *privf)
{
    gchar *key = NULL;
    otr4_client_adapter_t *client = NULL;

    char *line = NULL;
    size_t cap = 0;
    int len = 0;

    if (!privf)
        return;

    while ((len = getline(&line, &cap, privf)) != -1) {
        key = g_strndup(line, len-1);
        client = otr4_client_from_key(key);
        //TODO: What to do if an error happens?
        otr4_client_adapter_read_privkey_FILEp(client, privf);
    }
}

static int
otr4_privkey_generate_FILEp(const otr4_client_t * client, const char *key, FILE * privf)
{
        char *buff = NULL;
        size_t s = 0;
        int err = 0;

        if (!privf)
                return -1;

        if (!client->keypair)
                return -2;

        err = otrv4_symmetric_key_serialize(&buff, &s, client->keypair->sym);
        if (err)
                return err;

        if (EOF == fputs(key, privf))
                return -3;

        if (EOF == fputs("\n", privf))
                return -3;

        if (1 != fwrite(buff, s, 1, privf))
                return -3;

        if (EOF == fputs("\n", privf))
                return -3;

        return 0;
}


static void
add_privkey_to_file(gpointer key,
           gpointer value,
           gpointer user_data)
{
    otr4_client_adapter_t *client = value;
    FILE *privf = user_data;

    //TODO: What if an error hapens?
    otr4_privkey_generate_FILEp(client->real_client, key, privf);
}

void
otr4_privkey_write_FILEp(FILE *privf) {
        g_hash_table_foreach(client_table, add_privkey_to_file, privf);
}


otr4_client_adapter_t*
otr4_client_adapter_new(const otrv4_callbacks_t *callbacks) {
    otr4_client_adapter_t *c = malloc(sizeof(otr4_client_adapter_t));
    if (!c)
        return NULL;

    c->account = NULL;
    c->protocol = NULL;
    c->real_client = otr4_client_new(NULL);
    c->real_client->callbacks = callbacks;
    c->plugin_conversations = NULL;

    return c;
}

void
otr4_client_adapter_free(otr4_client_adapter_t *client) {
    free(client->account);
    client->account = NULL;

    free(client->protocol);
    client->protocol = NULL;

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

static ConnContext*
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
    if (otr4_client_adapter_get_context(conv, client)) {
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

otr4_client_adapter_t* otr4_get_client(const otr4_client_conversation_t* conv)
{
    return otr4_client(conv->account, conv->protocol);
}
