#include "otr4-client.h"

#include <stdio.h>
#include "otr-plugin.h"

//TODO: This client_adapter should be removed.
//It does not adapts the client anymore (by adding ConnContext to each
//conversation).

//TODO: REMOVE
static GHashTable *client_table = NULL;

/*
static const otr4_conversation_t *
otr4_client_adapter_get_conversation_from_connection(const otrv4_t *wanted, const otr4_client_adapter_t *client) {
    if (!wanted)
        return NULL;

    list_element_t *el = NULL;
    for (el = client->conversations; el; el = el->next) {
        otr4_conversation_t *conv = (otr4_conversation_t*) el->data;
        if (conv->conn == wanted)
            return conv;
    }

    return NULL;
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

    //TODO: This should come from the state's opdata
    //TODO: What about the peer?

    //client_conv->account = client->account;
    //client_conv->protocol = client->protocol;
    client_conv->peer = conv->recipient;
    //uint16_t their_instance_tag;
    //uint16_t our_instance_tag;

    return client_conv;
}

static void otr4_create_privkey_cb(const otrv4_t *conn)
{
    if (!callback_v4 || !callback_v4->create_privkey)
        return;

    otr4_client_conversation_t* client_conv = conn_to_conv(conn);
    callback_v4->create_privkey(client_conv);
    free(client_conv);
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

static void otr4_confirm_otr3_fingerprint_cb(const otrv3_fingerprint_t fp, const otrv4_t *conn)
{
    if (!callback_v4 || !callback_v4->fingerprint_seen_otr3)
        return;

    otr4_client_conversation_t* client_conv = conn_to_conv(conn);
    callback_v4->fingerprint_seen_otr3(fp, client_conv);
    free(client_conv);
}

static void otr4_handle_smp_event_cb(const otr4_smp_event_t event,
             const uint8_t progress_percent, const char *question,
             const otrv4_t *conn)
{
    otr4_client_conversation_t* client_conv = NULL;
    if (!callback_v4)
        return;

    client_conv = conn_to_conv(conn);

    switch (event) {
	case OTRV4_SMPEVENT_ASK_FOR_SECRET :
            if (!callback_v4->smp_ask_for_secret)
                return;

            callback_v4->smp_ask_for_secret(client_conv);
	    break;
	case OTRV4_SMPEVENT_ASK_FOR_ANSWER :
            if (!callback_v4->smp_ask_for_answer)
                return;

            callback_v4->smp_ask_for_answer(question, client_conv);
	    break;
	case OTRV4_SMPEVENT_CHEATED :
	case OTRV4_SMPEVENT_IN_PROGRESS :
	case OTRV4_SMPEVENT_SUCCESS :
	case OTRV4_SMPEVENT_FAILURE :
	case OTRV4_SMPEVENT_ABORT :
	case OTRV4_SMPEVENT_ERROR :
            if (!callback_v4->smp_update)
                return;

            callback_v4->smp_update(event, progress_percent, client_conv);
	    break;
        default:
            //OTRV4_SMPEVENT_NONE. Should not be used.
            break;
    }

    free(client_conv);
}

//This will forward libotr callbacks (they only know about otrv4 connections)
//to plugin callbacks (they know about having multiple accounts in mutiple
//protocols and so on)
static otrv4_callbacks_t otr4_callbacks = {
    NULL, //otr4_create_privkey_cb,
    NULL, //otr4_gone_secure_cb,
    NULL, //otr4_gone_insecure_cb,
    NULL, //otr4_confirm_fingerprint_cb,
    NULL, //otr4_confirm_otr3_fingerprint_cb,
    NULL, //otr4_handle_smp_event_cb,
};

*/

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

/*
static
otr4_client_adapter_t*
get_otr4_client(const char *accountname, const char *protocol)
{
    otr4_client_adapter_t *ret = NULL;
    char *key = NULL;

    asprintf(&key, "%s:%s", protocol, accountname);
    if (!key)
        return NULL;

    ret = g_hash_table_lookup(client_table, key);
    free(key);
    
    return ret;
}

otr4_client_adapter_t*
otr4_client_adapter_new(const otrv4_callbacks_t *callbacks,
    OtrlUserState userstate, const char *protocol, const char *account)
{
    otr4_client_adapter_t *c = malloc(sizeof(otr4_client_adapter_t));
    if (!c)
        return NULL;

    c->protocol = g_strdup(protocol);
    c->account = g_strdup(account);
    c->real_client = otr4_client_new(NULL, userstate, protocol, account);
    c->real_client->callbacks = callbacks;

    return c;
}
*/

void
otr4_client_adapter_free(otr4_client_adapter_t *client) {
    otr4_client_free(client);
}

char*
otr4_client_adapter_query_message(const char *recipient,
                          const char* message,
                          otr4_client_adapter_t *client) {
    return otr4_client_query_message(recipient, message, client);
}

int
otr4_client_adapter_send(char **newmessage,
                 const char *message,
                 const char *recipient,
                 otr4_client_adapter_t *client) {
    return otr4_client_send(newmessage, message, recipient, client);
}

int
otr4_client_adapter_receive(char **newmessage,
                    char **todisplay,
                    const char *message,
                    const char *recipient,
                    otr4_client_adapter_t *client) {
    return otr4_client_receive(newmessage, todisplay, message, recipient, client);
}

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client)
{
    char *ret = NULL;

    otrv4_fingerprint_t our_fp = {0};
    if (otr4_client_get_our_fingerprint(our_fp, client))
        return NULL;

    ret = malloc(OTR4_FPRINT_HUMAN_LEN);
    if (!ret)
        return NULL;

    otr4_fingerprint_hash_to_human(ret, our_fp);
    return ret;
}

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client)
{
    return otr4_client_disconnect(newmessage, recipient, client);
}

int otr4_client_adapter_smp_start(char **tosend, const char *recipient,
    const char *question, const unsigned char *secret, size_t secretlen,
    otr4_client_adapter_t * client)
{
    return otr4_client_smp_start(tosend, recipient, question,
        secret, secretlen, client);
}

int otr4_client_adapter_smp_respond(char **tosend, const char *recipient,
     const unsigned char *secret, size_t secretlen, otr4_client_adapter_t * client)
{
    return otr4_client_smp_respond(tosend, recipient, secret, secretlen,
        client);
}

