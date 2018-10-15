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

#include "long_term_keys.h"

#include <libotr-ng/client.h>
#include <libotr-ng/messaging.h>

#include "gtk-dialog.h"
#include "persistance.h"
#include "pidgin-helpers.h"
#include "ui.h"

extern otrng_global_state_s *otrng_state;

/* Generate a private key for the given accountname/protocol */
void long_term_keys_create_privkey_v4(otrng_client_s *client) {
  PurpleAccount *account = client_id_to_purple_account(client->client_id);
  if (otrng_succeeded(otrng_global_state_generate_private_key(
          otrng_state, purple_account_to_client_id(account)))) {
    otrng_ui_update_fingerprint();
  }
}

static void load_private_key_v4(otrng_client_s *client) {
  persistance_read_private_keys_v4(otrng_state);
}

static void store_private_key_v4(otrng_client_s *client) {
  persistance_write_privkey_v4_FILEp(otrng_state);
}

static void create_forging_key(otrng_client_s *client) {
  otrng_global_state_generate_forging_key(otrng_state, client->client_id);
}

static void load_forging_key(struct otrng_client_s *client) {
  persistance_read_forging_key(otrng_state);
}

static void store_forging_key(struct otrng_client_s *client) {
  persistance_write_forging_key(otrng_state);
}

void long_term_keys_create_private_key_v3(otrng_client_s *client) {
  if (otrng_succeeded(otrng_global_state_generate_private_key_v3(
          otrng_state, client->client_id))) {
    otrng_ui_update_fingerprint();
  }
}

static void load_private_key_v3(otrng_client_s *client) {
  persistance_read_private_keys_v3(otrng_state);
}

static void store_private_key_v3(otrng_client_s *client) {
  persistance_write_private_keys_v3(otrng_state);
}

void long_term_keys_set_callbacks(otrng_client_callbacks_s *callbacks) {
  callbacks->create_privkey_v4 = long_term_keys_create_privkey_v4;
  callbacks->load_privkey_v4 = load_private_key_v4;
  callbacks->store_privkey_v4 = store_private_key_v4;
  callbacks->create_forging_key = create_forging_key;
  callbacks->load_forging_key = load_forging_key;
  callbacks->store_forging_key = store_forging_key;
  callbacks->create_privkey_v3 = long_term_keys_create_private_key_v3;
  callbacks->store_privkey_v3 = store_private_key_v3;
  callbacks->load_privkey_v3 = load_private_key_v3;
}
