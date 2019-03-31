/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2018  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *                           The pidgin-otrng contributors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PREKEY_DISCOVERY_JABBER_H_
#define _PREKEY_DISCOVERY_JABBER_H_

#include "account.h"
#include "prekey-discovery.h"

#define NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"

typedef void (*XmppIqCallback)(PurpleConnection *pc, const char *type,
                               const char *id, const char *from, xmlnode *iq,
                               gpointer data);

typedef struct {
  XmppIqCallback next;
  PrekeyServerResult result_cb;
  void *context;
} otrng_plugin_prekey_discovery_status;

// returns 1 on success and 0 on failure
int otrng_plugin_jabber_lookup_prekey_servers_for(PurpleAccount *account,
                                                  const char *who,
                                                  PrekeyServerResult result_cb,
                                                  void *context);

char *otrng_plugin_jabber_prekey_domain_for(PurpleAccount *account,
                                            const char *who);

void otrng_plugin_prekey_discovery_jabber_load();
void otrng_plugin_prekey_discovery_jabber_unload();

#endif /* _PREKEY_DISCOVERY_JABBER_H_ */
