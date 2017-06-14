#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <glib.h>
#include <libotr/context.h>
#include <libotr4/client.h>

//TODO: REMOVE this type
typedef otr4_client_t otr4_client_adapter_t;

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

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client);

int
otr4_client_generate_privkey(otr4_client_adapter_t *client);

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client);

int otr4_client_adapter_smp_start(char **tosend, const char *recipient,
    const char *question, const unsigned char *secret, size_t secretlen,
    otr4_client_adapter_t * client);

int otr4_client_adapter_smp_respond(char **tosend, const char *recipient,
     const unsigned char *secret, size_t secretlen, otr4_client_adapter_t * client);

void otrv4_userstate_create(void);
void otrv4_userstate_destroy(void);

#endif
