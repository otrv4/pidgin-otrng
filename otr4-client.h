#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <glib.h>
#include <libotr/context.h>
#include <libotr4/client.h>

typedef struct {
  ConnContext *ctx;
  otr4_conversation_t *conv;
} otr4_plugin_conversation_t;

typedef struct {
    char *account;
    char *protocol;
    char *peer;

    uint16_t their_instance_tag;
    uint16_t our_instance_tag;
} otrv4_conversarion_rename_t;

typedef struct {
        /* A connection has entered a secure state. */
        void (*gone_secure) (const otrv4_t *);

        /* A connection has left a secure state. */
        void (*gone_insecure) (const otrv4_t *);

        /* A fingerprint was seen in this connection. */
        void (*fingerprint_seen) (const otrv4_fingerprint_t, const otrv4_t *);
} otrv4_plugin_callbacks_t;

typedef struct {
  char *account;
  char *protocol;

  list_element_t *plugin_conversations;
  otr4_client_t *real_client;
} otr4_client_adapter_t;

otr4_client_adapter_t*
otr4_client_adapter_new(const otrv4_callbacks_t *cb);

void
otr4_client_adapter_free(otr4_client_adapter_t *client);

char*
otr4_client_adapter_query_message(const char *recipient,
                          const char* message,
                          otr4_client_adapter_t *client);

int
otr4_client_adapter_send(char **newmessage,
                 const char *message,
                 const char *recipient,
                 otr4_client_adapter_t *client);

int
otr4_client_adapter_receive(char **newmessage,
                    char **todisplay,
                    const char *message,
                    const char *recipient,
                    otr4_client_adapter_t *client);

void
otr4_client_adapter_set_context(const char* recipient, ConnContext *ctx, otr4_client_adapter_t *client);

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client);

int
otr4_client_adapter_read_privkey_FILEp(otr4_client_adapter_t *client, FILE *privf);

int
otr4_client_generate_privkey(otr4_client_adapter_t *client);

const otr4_conversation_t *
otr4_client_adapter_get_conversation_from_connection(const otrv4_t *conn, const otr4_client_adapter_t *client);

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client);
// Where is it used?
typedef struct {
    char *account;
    char *protocol;

    //state
    otrl_instag_t our_instance;

} otr4_account_t;

void
otr4_account_free(otr4_account_t *account);


void otr4_callbacks_set(const otrv4_callbacks_t *otr4_callbacks);
void otrv4_userstate_create(void);
void otrv4_userstate_destroy(void);
otr4_client_adapter_t* otr4_client_from_key(char *key);
otr4_client_adapter_t* otr4_client(const char *accountname, const char *protocol);
otr4_client_adapter_t* otr4_connection_to_client(const otrv4_t *conn);
void otr4_privkey_read_FILEp(FILE *privf);
void otr4_privkey_write_FILEp(FILE *privf);

#endif 
