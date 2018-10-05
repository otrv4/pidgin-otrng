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
#include "prekeys.h"
#include <libotr-ng/debug.h>

extern otrng_global_state_s *otrng_state;

static void load_prekey_messages(otrng_client_s *client) {
  persistance_read_prekey_messages(otrng_state);
}

static void store_prekey_messages(otrng_client_s *client) {
  persistance_write_prekey_messages(otrng_state);
}

void prekeys_set_callbacks(otrng_client_callbacks_s *callbacks) {
  callbacks->load_prekey_messages = load_prekey_messages;
  callbacks->store_prekey_messages = store_prekey_messages;
}
