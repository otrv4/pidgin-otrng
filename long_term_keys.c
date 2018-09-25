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

#include <account.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "long_term_keys.h"

#include <libotr-ng/client.h>
#include <libotr-ng/messaging.h>

#include "pidgin-helpers.h"

extern otrng_global_state_s *otrng_state;

static void load_private_keys_v4(const otrng_client_id_s opdata) {
  gchar *f = g_build_filename(purple_user_dir(), PRIVKEYFNAMEv4, NULL);
  if (!f) {
    return;
  }

  FILE *fp = g_fopen(f, "rb");
  g_free(f);

  otrng_global_state_private_key_v4_read_FILEp(
      otrng_state, fp, protocol_and_account_to_purple_conversation);

  if (fp) {
    fclose(fp);
  }
}

void long_term_keys_init_userstate(otrng_client_callbacks_s *callbacks) {
  callbacks->load_privkey_v4 = load_private_keys_v4;
}
