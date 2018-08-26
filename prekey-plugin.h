/* Purple headers */
#include <account.h>
#include <plugin.h>

#include <libotr-ng/prekey_client.h>

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN
#define OTRNG_PIDGIN_PREKEY_PLUGIN

#include <libotr-ng/client.h>
#include <libotr-ng/prekey_client.h>

typedef struct {
  PurpleAccount *account;
  char *message;
  char *recipient;
} otrng_plugin_offline_message_ctx;

typedef void (*WithPrekeyClient)(PurpleAccount *, otrng_client_s *,
                                 otrng_prekey_client_s *, void *);

void otrng_plugin_get_prekey_client(PurpleAccount *account, WithPrekeyClient cb,
                                    void *ctx);

gboolean otrng_prekey_plugin_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_unload(PurplePlugin *handle);

#endif
