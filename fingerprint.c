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

GHashTable *otrng_fingerprints_table = NULL;

void (*update_keylist)(void) = NULL;
void (*update_fingerprint)(void) = NULL;
void (*resensitize)(void) = NULL;
void (*unknown_fingerprint)(OtrlUserState, const char *, const char *,
                            const char *, const unsigned char[20]) = NULL;

static void destroy_plugin_fingerprint(gpointer data) {
  otrng_plugin_fingerprint *fp = data;

  free(fp->protocol);
  free(fp->account);
  free(fp->username);
  free(fp);
}

static void fingerprint_store_create() {
  otrng_fingerprints_table = g_hash_table_new_full(
      g_str_hash, g_str_equal, g_free, destroy_plugin_fingerprint);
}

otrng_plugin_fingerprint *
otrng_plugin_fingerprint_get(const char fp[OTRNG_FPRINT_HUMAN_LEN]) {
  return g_hash_table_lookup(otrng_fingerprints_table, fp);
}

otrng_plugin_fingerprint *
otrng_plugin_fingerprint_new(const char fp[OTRNG_FPRINT_HUMAN_LEN],
                             const char *protocol, const char *account,
                             const char *peer) {
  otrng_plugin_fingerprint *info = malloc(sizeof(otrng_plugin_fingerprint));
  if (!info) {
    return NULL;
  }

  info->trusted = 0;
  memcpy(info->fp, fp, OTRNG_FPRINT_HUMAN_LEN);
  info->protocol = g_strdup(protocol);
  info->account = g_strdup(account);
  info->username = g_strdup(peer);

  char *key = g_strdup(fp);
  g_hash_table_insert(otrng_fingerprints_table, key, info);
  return info;
}

void confirm_fingerprint_cb_v3(void *opdata, OtrlUserState us,
                               const char *accountname, const char *protocol,
                               const char *username,
                               unsigned char fingerprint[20]) {
  unknown_fingerprint(us, accountname, protocol, username, fingerprint);
}

void write_fingerprints_cb_v3(void *opdata) {
  otrng_plugin_write_fingerprints();
  update_keylist();
  resensitize();
}

static void add_fingerprint_to_file(gpointer key, gpointer value,
                                    gpointer user_data) {
  otrng_plugin_fingerprint *fp = value;
  FILE *storef = user_data;

  fprintf(storef, "%s\t%s\t%s\t", fp->username, fp->account, fp->protocol);
  fprintf(storef, "%s\t%s\n", fp->fp, fp->trusted ? "trusted" : "");
}

void otrng_plugin_write_fingerprints_v4(void) {
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */
  FILE *storef;
  gchar *storefile =
      g_build_filename(purple_user_dir(), FINGERPRINT_STORE_FILE_NAME_V4, NULL);
#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */
  storef = g_fopen(storefile, "wb");
#ifndef WIN32
  umask(mask);
#endif /* WIN32 */
  g_free(storefile);
  if (!storef) {
    return;
  }

  g_hash_table_foreach(otrng_fingerprints_table, add_fingerprint_to_file,
                       storef);

  fclose(storef);
}

/* Write the fingerprints to disk. */
void otrng_plugin_write_fingerprints(void) {
  // TODO: write otrv3 fingerprints
  otrng_plugin_write_fingerprints_v4();
}

static void read_fingerprints_FILEp(FILE *storef) {
  char storeline[1000];
  size_t maxsize = sizeof(storeline);

  if (!storef) {
    return;
  }

  while (fgets(storeline, maxsize, storef)) {
    char *username;
    char *accountname;
    char *protocol;
    char *fp_human;
    char *trust;
    char *tab;
    char *eol;
    otrng_plugin_fingerprint *fng;

    /* Parse the line, which should be of the form:
     *    username\taccountname\tprotocol\t40_hex_nybbles\n          */
    username = storeline;
    tab = strchr(username, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    accountname = tab + 1;
    tab = strchr(accountname, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    protocol = tab + 1;
    tab = strchr(protocol, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    fp_human = tab + 1;
    tab = strchr(fp_human, '\t');
    if (!tab) {
      eol = strchr(fp_human, '\r');
      if (!eol) {
        eol = strchr(fp_human, '\n');
      }
      if (!eol) {
        continue;
      }
      *eol = '\0';
      trust = NULL;
    } else {
      *tab = '\0';
      trust = tab + 1;
      eol = strchr(trust, '\r');
      if (!eol) {
        eol = strchr(trust, '\n');
      }
      if (!eol) {
        continue;
      }
      *eol = '\0';
    }

    if (strlen(fp_human) != OTRNG_FPRINT_HUMAN_LEN - 1) {
      continue;
    }

    fng = otrng_plugin_fingerprint_get(fp_human);
    if (!fng) {
      fng = otrng_plugin_fingerprint_new(fp_human, protocol, accountname,
                                         username);
    }

    if (!fng) {
      continue;
    }

    fng->trusted = strlen(trust) ? 1 : 0;
  }
}

static void fingerprint_seen_v3(const otrng_fingerprint_v3 fp,
                                const otrng_s *cconv) {
  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  unknown_fingerprint(otrng_state->user_state_v3, conv->account, conv->protocol,
                      conv->peer, fp);
  otrng_plugin_conversation_free(conv);
}

static void fingerprint_seen_v4(const otrng_fingerprint fp,
                                const otrng_s *cconv) {
  // TODO: use fp to determine if you have seen this fp before
  // See: otrng_dialog_unknown_fingerprint
  // (otrng_gtk_dialog_unknown_fingerprint)
  char *buf;
  char fp_human[OTRNG_FPRINT_HUMAN_LEN];

  otrng_fingerprint_hash_to_human(fp_human, fp);
  if (otrng_plugin_fingerprint_get(fp_human)) {
    return;
  }

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  // TODO: Change the message if we have have already seen another FP for this
  // contact.

  otrng_plugin_fingerprint *info = otrng_plugin_fingerprint_new(
      fp_human, conv->protocol, conv->account, conv->peer);

  if (!info) {
    otrng_plugin_conversation_free(conv);
    return; // ERROR
  }

  buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
                          "should authenticate this buddy."),
                        info->username);

  PurpleConversation *purple_conv = otrng_plugin_userinfo_to_conv(
      conv->account, conv->protocol, conv->peer, 0);

  purple_conversation_write(purple_conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
                            time(NULL));

  otrng_plugin_conversation_free(conv);
  g_free(buf);
}

static gboolean find_active_fingerprint(gpointer key, gpointer value,
                                        gpointer user_data) {
  otrng_plugin_fingerprint *info = value;

  // TODO: get the "active" and not the first.
  if (!strcmp(info->username, user_data)) {
    return TRUE;
  }

  return FALSE;
}

otrng_conversation_s *
otrng_plugin_fingerprint_to_otr_conversation(otrng_plugin_fingerprint *f) {
  otrng_client_s *client = NULL;

  if (!f) {
    return NULL;
  }

  client = get_otrng_client(f->protocol, f->account);
  if (!client) {
    return NULL;
  }

  return otrng_client_get_conversation(0, f->username, client);
}

GList *otrng_plugin_fingerprint_get_all(void) {
  return g_hash_table_get_values(otrng_fingerprints_table);
}

otrng_plugin_fingerprint *
otrng_plugin_fingerprint_get_active(const char *peer) {
  return g_hash_table_find(otrng_fingerprints_table, find_active_fingerprint,
                           (gpointer)peer);
}

void otrng_plugin_fingerprint_forget(const char fp[OTRNG_FPRINT_HUMAN_LEN]) {
  g_hash_table_remove(otrng_fingerprints_table, fp);
}

void otrng_fingerprints_set_callbacks(otrng_client_callbacks_s *cb) {
  cb->fingerprint_seen = fingerprint_seen_v4;
  cb->fingerprint_seen_v3 = fingerprint_seen_v3;
}

gboolean otrng_plugin_fingerprints_load(
    PurplePlugin *handle, void (*update_keylist_init)(void),
    void (*update_fingerprint_init)(void), void (*resensitize_init)(void),
    void (*unknown_fingerprint_init)(OtrlUserState, const char *, const char *,
                                     const char *, const unsigned char[20])) {
  update_keylist = update_keylist_init;
  update_fingerprint = update_fingerprint_init;
  resensitize = resensitize_init;
  unknown_fingerprint = unknown_fingerprint_init;

  gchar *f =
      g_build_filename(purple_user_dir(), FINGERPRINT_STORE_FILE_NAME_V4, NULL);
  if (!f) {
    return FALSE;
  }
  FILE *fp = g_fopen(f, "rb");
  g_free(f);

  fingerprint_store_create();
  read_fingerprints_FILEp(fp);
  update_fingerprint();

  if (fp) {
    fclose(fp);
  }

  return TRUE;
}

gboolean otrng_plugin_fingerprints_unload(PurplePlugin *handle) {
  g_hash_table_remove_all(otrng_fingerprints_table);
  update_fingerprint();

  otrng_fingerprints_table = NULL;
  update_keylist = NULL;
  update_fingerprint = NULL;
  resensitize = NULL;
  unknown_fingerprint = NULL;

  return TRUE;
}
