/* Purple headers */
#include <account.h>
#include <plugin.h>

#include <libotr-ng/prekey_client.h>

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN
#define OTRNG_PIDGIN_PREKEY_PLUGIN

gboolean otrng_prekey_plugin_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_unload(PurplePlugin *handle);

#endif
