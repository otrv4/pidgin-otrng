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

static void create_client_profile(otrng_client_s *client) {
  otrng_global_state_generate_client_profile(otrng_state, client->client_id);
}

static void load_client_profile(otrng_client_s *client) {
  persistance_read_client_profile(otrng_state);
}

static void create_prekey_profile(otrng_client_s *client) {
  otrng_global_state_generate_prekey_profile(otrng_state, client->client_id);
}

static void load_prekey_profile(otrng_client_s *client) {
  persistance_read_prekey_profile(otrng_state);
}

static void store_client_profile(otrng_client_s *client) {
  persistance_write_client_profile_FILEp(otrng_state);
}

static void store_prekey_profile(otrng_client_s *client) {
  persistance_write_prekey_profile_FILEp(otrng_state);
}

static void store_expired_client_profile(otrng_client_s *client) {
  persistance_write_expired_client_profile(otrng_state);
}

static void load_expired_client_profile(otrng_client_s *client) {
  persistance_read_expired_client_profile(otrng_state);
}

static void store_expired_prekey_profile(otrng_client_s *client) {
  persistance_write_expired_prekey_profile(otrng_state);
}

static void load_expired_prekey_profile(otrng_client_s *client) {
  persistance_read_expired_prekey_profile(otrng_state);
}

void profiles_set_callbacks(otrng_client_callbacks_s *callbacks) {
  callbacks->create_client_profile = create_client_profile;
  callbacks->load_client_profile = load_client_profile;
  callbacks->store_client_profile = store_client_profile;
  callbacks->create_prekey_profile = create_prekey_profile;
  callbacks->load_prekey_profile = load_prekey_profile;
  callbacks->store_prekey_profile = store_prekey_profile;
  callbacks->load_expired_client_profile = load_expired_client_profile;
  callbacks->store_expired_client_profile = store_expired_client_profile;
  callbacks->load_expired_prekey_profile = load_expired_prekey_profile;
  callbacks->store_expired_prekey_profile = store_expired_prekey_profile;
}
