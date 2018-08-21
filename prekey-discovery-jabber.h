/*
 * TODO: insert proper copyrights
 */

#ifndef _PREKEY_DISCOVERY_JABBER_H_
#define _PREKEY_DISCOVERY_JABBER_H_

#include "account.h"
#include "prekey-discovery.h"

#define NS_DISCO_INFO       "http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS      "http://jabber.org/protocol/disco#items"

typedef void (*XmppIqCallback)(PurpleConnection *pc, const char *type,
                               const char *id, const char *from, xmlnode *iq,
                               gpointer data);

typedef struct {
    XmppIqCallback next;
    PrekeyServerResult result_cb;
} otrng_plugin_prekey_discovery_status;

// returns 1 on success and 0 on failure
int otrng_plugin_jabber_lookup_prekey_servers_for(PurpleAccount *account,
                                                  const char *who,
                                                  PrekeyServerResult result_cb);

void otrng_plugin_prekey_discovery_jabber_load();
void otrng_plugin_prekey_discovery_jabber_unload();


#endif /* _PREKEY_DISCOVERY_JABBER_H_ */
