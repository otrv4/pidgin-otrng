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

#ifndef _PREKEY_DISCOVERY_H_
#define _PREKEY_DISCOVERY_H_

#include "account.h"

#define FINGERPRINT_LENGTH 56

typedef struct {
  char *identity;
  char fingerprint[FINGERPRINT_LENGTH];
} otrng_plugin_prekey_server;

typedef void (*PrekeyServerResult)(otrng_plugin_prekey_server *, void *);

/**
 * This function will try to look up prekey servers for the account
 * given. If any failure is encountered, it will return 0.
 * The given result_cb will be called once for each prekey server found.
 * The argument given to the callback is owned by the receiver, including
 * the values inside.
 */
int otrng_plugin_lookup_prekey_servers_for_self(PurpleAccount *account,
                                                PrekeyServerResult result_cb,
                                                void *context);

/**
 * This function will try to look up prekey servers for the buddy given.
 * If any failure is encountered, it will return 0.
 * The given result_cb will be called once for each prekey server found.
 * The argument given to the callback is owned by the receiver, including
 * the values inside.
 */
int otrng_plugin_lookup_prekey_servers_for(PurpleAccount *account,
                                           const char *who,
                                           PrekeyServerResult result_cb,
                                           void *context);

char *otrng_plugin_prekey_domain_for(PurpleAccount *account, const char *who);

/**
 * Has to be called to initialize this part of the plugin.
 */
void otrng_plugin_prekey_discovery_load();

/**
 * Has to be called to uninitialize this part of the plugin.
 */
void otrng_plugin_prekey_discovery_unload();

#endif /* _PREKEY_DISCOVERY_H_ */
