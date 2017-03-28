#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <libotr/context.h>
#include <libotr4/client.h>

//The current plugin requires a ConnContext
typedef struct {
  //const char *username;
  //const char* accountname;
  //const char* proto; //???
  //otrl_instag_t their_instance;
  //otrl_instag_t our_instance;

  ConnContext *ctx;
  otr4_conversation_t *conv;
} otr4_plugin_conversation_t;

typedef struct {
  list_element_t *plugin_conversations;
  otr4_client_t *real_client;
} otr4_client_adapter_t;

otr4_client_adapter_t*
otr4_client_adapter_new(otrv4_callbacks_t *cb);

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

ConnContext*
otr4_client_adapter_get_context(const otr4_conversation_t *conv, otr4_client_adapter_t *client);

void
otr4_client_adapter_set_context(const char* recipient, ConnContext *ctx, otr4_client_adapter_t *client);

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client);

int
otr4_client_adapter_read_privkey_FILEp(otr4_client_adapter_t *client, FILE *privf);

int
otr4_client_generate_privkey(otr4_client_adapter_t *client);

int
otr4_client_adapter_privkey_generate_FILEp(otr4_client_adapter_t *client, FILE *privf);

const otr4_conversation_t *
otr4_client_adapter_get_conversation_from_connection(const otrv4_t *conn, const otr4_client_adapter_t *client);

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client);

typedef struct {
    char *account;
    char *protocol;

    //state
    otrl_instag_t our_instance;

} otr4_account_t;

void
otr4_account_free(otr4_account_t *account);

#endif 
