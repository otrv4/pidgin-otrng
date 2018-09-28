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

void long_term_keys_load_private_key_v4(const otrng_client_id_s opdata) {
  persistance_load_private_keys_v4(otrng_state);
}

/* Generate a private key for the given accountname/protocol */
void long_term_keys_create_privkey_v4(const otrng_client_id_s opdata) {
  PurpleAccount *account = client_id_to_purple_account(opdata);
  OtrgDialogWaitHandle waithandle;

  const char *accountname = purple_account_get_username(account);
  const char *protocol = purple_account_get_protocol_id(account);

  waithandle = otrng_dialog_private_key_wait_start(accountname, protocol);

  if (otrng_succeeded(otrng_global_state_generate_private_key(
          otrng_state, purple_account_to_client_id(account)))) {
    // TODO: check the return value
    persistance_write_privkey_v4_FILEp(otrng_state);
    otrng_ui_update_fingerprint();
  }

  /* Mark the dialog as done. */
  otrng_dialog_private_key_wait_done(waithandle);
}

void long_term_keys_set_callbacks(otrng_client_callbacks_s *callbacks) {
  callbacks->create_privkey_v4 = &long_term_keys_create_privkey_v4;
  callbacks->load_privkey_v4 = &long_term_keys_load_private_key_v4;
}
