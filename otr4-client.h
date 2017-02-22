#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <libotr/context.h>
#include <libotr4/protocol.h>

typedef struct {
  //const char *username;
  //const char* accountname;
  //const char* proto; //???
  //otrl_instag_t their_instance;
  //otrl_instag_t our_instance;
  ConnContext *ctx;
  otrv4_t *conn;
} otr4_conversation_t;

typedef struct {
  /* A conversation has entered a secure state. */
  void (*gone_secure)(const otr4_conversation_t *conv);

  /* A conversation has left a secure state. */
  void (*gone_insecure)(const otr4_conversation_t *conv);
} otr4_client_callbacks_t;

//A client handle messages from/to a sender to/from multiple recipients.
typedef struct {
  otr4_client_callbacks_t *callbacks;

  cs_keypair_t keypair;

  //TODO: There should be multiple
  otr4_conversation_t *conv;
} otr4_client_t;

otr4_client_t*
otr4_client_new();

void
otr4_client_free(otr4_client_t *client);

int
otr4_client_send(char **newmessage, const char *message, const char *recipient, otr4_client_t *client);

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message, const char *recipient, otr4_client_t *client);

char*
otr4_client_query_message(const char *recipient, const char* message, otr4_client_t *client);

void
otr4_watch_context(ConnContext *ctx, otr4_client_t *client);

#endif
