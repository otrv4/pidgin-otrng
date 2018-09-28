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

#include <libotr-ng/messaging.h>

#include "persistance.h"
#include "pidgin-helpers.h"
#include "profiles.h"

extern otrng_global_state_s *otrng_state;

void profiles_create_client_profile(const PurpleAccount *account) {
  if (otrng_succeeded(otrng_global_state_generate_client_profile(
          otrng_state, purple_account_to_client_id(account)))) {
    // TODO: check the return error
    persistance_write_client_profile_FILEp(otrng_state);
    otrng_client_s *client = purple_account_to_otrng_client(account);
    otrng_prekey_client_set_client_profile_publication(client->prekey_client);
    // TODO: Update the UI if the client is displayed in the UI
  }
}

void profiles_load_client_profile(const otrng_client_id_s client_opdata) {
  persistance_read_client_profile(otrng_state);
}

// TODO: is this needed? make it consistent all over the place
static void create_client_profile(struct otrng_client_s *client,
                                  const otrng_client_id_s opdata) {
  profiles_create_client_profile(client_id_to_purple_account(opdata));
}

void profiles_set_callbacks(otrng_client_callbacks_s *callbacks) {
  callbacks->create_client_profile = create_client_profile;
  callbacks->load_client_profile = profiles_load_client_profile;
}
