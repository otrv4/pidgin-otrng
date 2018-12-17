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

#include <stdlib.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "fingerprint.h"
#include "persistance.h"
#include "pidgin-helpers.h"
#include "plugin-conversation.h"

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

extern otrng_global_state_s *otrng_state;

void (*update_keylist)(void) = NULL;
void (*update_fingerprint)(void) = NULL;
void (*resensitize)(void) = NULL;
void (*unknown_fingerprint_v3)(OtrlUserState, const char *, const char *,
                               const char *, const unsigned char[20]) = NULL;

void confirm_fingerprint_cb_v3(void *opdata, OtrlUserState us,
                               const char *accountname, const char *protocol,
                               const char *username,
                               unsigned char fingerprint[20]) {
  unknown_fingerprint_v3(us, accountname, protocol, username, fingerprint);
}

void write_fingerprints_cb_v3(void *opdata) {
  otrng_plugin_write_fingerprints();
  update_keylist();
  resensitize();
}

void otrng_plugin_write_fingerprints(void) {
  // TODO: write otrv3 fingerprints
  persistance_write_fingerprints_v4(otrng_state);
}

// TODO: OB - I think we should revisit how these fingerprint_seen callbacks
// work so that they are unified between v3 and v4. I'm not sure the logic is
// completely correct at the moment.

static void fingerprint_seen_v3(const otrng_fingerprint_v3 fp,
                                const otrng_s *cconv) {
  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  unknown_fingerprint_v3(otrng_state->user_state_v3, conv->account,
                         conv->protocol, conv->peer, fp);
  otrng_plugin_conversation_free(conv);
}

static void fingerprint_seen_v4(const otrng_fingerprint fp,
                                const otrng_s *cconv) {
  if (otrng_fingerprint_get_by_fp(cconv->client, fp) != NULL) {
    return;
  }

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  int seen =
      otrng_fingerprint_get_by_username(cconv->client, conv->peer) != NULL;

  otrng_fingerprint_add(cconv->client, fp, conv->peer, otrng_false);

  char *buf;
  if (seen) {
    buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
                            "should authenticate this buddy.  We have seen "
                            "this buddy with another fingerprint."),
                          conv->peer);
  } else {
    buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
                            "should authenticate this buddy."),
                          conv->peer);
  }

  PurpleConversation *purple_conv = otrng_plugin_userinfo_to_conv(
      conv->account, conv->protocol, conv->peer, 0);

  purple_conversation_write(purple_conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
                            time(NULL));

  otrng_plugin_conversation_free(conv);
  g_free(buf);
}

otrng_conversation_s *
otrng_plugin_fingerprint_to_otr_conversation(otrng_client_s *client,
                                             otrng_known_fingerprint_s *f) {
  if (!f || !client) {
    return NULL;
  }

  return otrng_client_get_conversation(0, f->username, client);
}

otrng_known_fingerprint_s *
otrng_plugin_fingerprint_get_active(const otrng_plugin_conversation *conv) {
  return otrng_fingerprint_get_current(conv->conv);
}

void otrng_plugin_fingerprint_forget(otrng_client_s *client,
                                     otrng_known_fingerprint_s *fp) {
  otrng_fingerprint_forget(client, fp);
}

static void fingerprint_store_v4(otrng_client_s *client) {
  persistance_write_fingerprints_v4(otrng_state);
}

static void fingerprint_load_v4(otrng_client_s *client) {
  persistance_read_fingerprints_v4(otrng_state);
  update_fingerprint();
}

void otrng_fingerprints_set_callbacks(otrng_client_callbacks_s *cb) {
  cb->fingerprint_seen = fingerprint_seen_v4;
  cb->fingerprint_seen_v3 = fingerprint_seen_v3;
  cb->store_fingerprints_v4 = fingerprint_store_v4;
  cb->load_fingerprints_v4 = fingerprint_load_v4;
}

gboolean otrng_plugin_fingerprints_load(
    PurplePlugin *handle, void (*update_keylist_init)(void),
    void (*update_fingerprint_init)(void), void (*resensitize_init)(void),
    void (*unknown_fingerprint_v3_init)(OtrlUserState, const char *,
                                        const char *, const char *,
                                        const unsigned char[20])) {
  update_keylist = update_keylist_init;
  update_fingerprint = update_fingerprint_init;
  resensitize = resensitize_init;
  unknown_fingerprint_v3 = unknown_fingerprint_v3_init;
  return TRUE;
}

gboolean otrng_plugin_fingerprints_unload(PurplePlugin *handle) {
  otrng_global_state_clean_all(otrng_state);
  update_fingerprint();

  update_keylist = NULL;
  update_fingerprint = NULL;
  resensitize = NULL;
  unknown_fingerprint_v3 = NULL;

  return TRUE;
}
