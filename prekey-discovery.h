/*
 * TODO: insert proper copyrights
 */

#ifndef _PREKEY_DISCOVERY_H_
#define _PREKEY_DISCOVERY_H_

#include "account.h"

#define FINGERPRINT_LENGTH 56

typedef struct {
    char *identity;
    char fingerprint[FINGERPRINT_LENGTH];
} otrng_plugin_prekey_server;

typedef void (*PrekeyServerResult)(otrng_plugin_prekey_server*);

/**
 * This function will try to look up prekey servers for the account
 * given. If any failure is encountered, it will return 0.
 * The given result_cb will be called once for each prekey server found.
 * The argument given to the callback is owned by the receiver, including
 * the values inside.
 */
int otrng_plugin_lookup_prekey_servers_for_self(PurpleAccount *account,
                                                PrekeyServerResult result_cb);

/**
 * This function will try to look up prekey servers for the buddy given.
 * If any failure is encountered, it will return 0.
 * The given result_cb will be called once for each prekey server found.
 * The argument given to the callback is owned by the receiver, including
 * the values inside.
 */
int otrng_plugin_lookup_prekey_servers_for(PurpleAccount *account,
                                           const char *who,
                                           PrekeyServerResult result_cb);

/**
 * Has to be called to initialize this part of the plugin.
 */
void otrng_plugin_prekey_discovery_load();

/**
 * Has to be called to uninitialize this part of the plugin.
 */
void otrng_plugin_prekey_discovery_unload();


#endif /* _PREKEY_DISCOVERY_H_ */
