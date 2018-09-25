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

#include "fingerprint.h"

#include "pidgin-helpers.h"

extern GHashTable *otrng_fingerprints_table;

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
