#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <libotr4/protocol.h>

typedef struct {
  cs_keypair_t keypair;
  otrv4_t *connection;
} otr4_client_t;

otr4_client_t*
otr4_client_new();

void
otr4_client_free(otr4_client_t *client);

int
otr4_client_send(char **newmessage, const char *message, const char *recipient, otr4_client_t *client);

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message, const char *recipient, otr4_client_t *client);

#endif
