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

#ifndef __OTRNG_PERSISTANCE_H__
#define __OTRNG_PERSISTANCE_H__

#include <libotr-ng/messaging.h>

#define PRIVKEY_FILE_NAME_V4 "otr4.private_key"
#define PRIVKEY_FILE_NAME_V3 "otr.private_key"
#define CLIENT_PROFILE_FILE_NAME "otr4.client_profile"
#define PREKEY_PROFILE_FILE_NAME "otr4.prekey_profile"
#define PREKEYS_FILE_NAME "otr4.prekey_messages"
#define FORGING_KEY_FILE_NAME "otr4.forging_key"
#define EXP_CLIENT_PROFILE_FILE_NAME "otr4.exp_client_profile"
#define EXP_PREKEY_PROFILE_FILE_NAME "otr4.exp_prekey_profile"
#define FINGERPRINT_STORE_FILE_NAME_V4 "otr4.fingerprints"
#define FINGERPRINT_STORE_FILE_NAME_V3 "otr.fingerprints"

int persistance_write_privkey_v4_FILEp(otrng_global_state_s *otrng_state);

void persistance_read_private_keys_v4(otrng_global_state_s *otrng_state);

int persistance_write_client_profile_FILEp(otrng_global_state_s *otrng_state);

void persistance_read_client_profile(otrng_global_state_s *otrng_state);

int persistance_write_prekey_profile_FILEp(otrng_global_state_s *otrng_state);

void persistance_read_prekey_profile(otrng_global_state_s *otrng_state);

int persistance_write_prekey_messages(otrng_global_state_s *otrng_state);

void persistance_read_prekey_messages(otrng_global_state_s *otrng_state);

int persistance_write_forging_key(otrng_global_state_s *otrng_state);

void persistance_read_forging_key(otrng_global_state_s *otrng_state);

int persistance_write_expired_client_profile(otrng_global_state_s *otrng_state);

void persistance_read_expired_client_profile(otrng_global_state_s *otrng_state);

int persistance_write_expired_prekey_profile(otrng_global_state_s *otrng_state);

void persistance_read_expired_prekey_profile(otrng_global_state_s *otrng_state);

int persistance_write_private_keys_v3(otrng_global_state_s *otrng_state);

void persistance_read_private_keys_v3(otrng_global_state_s *otrng_state);

int persistance_write_fingerprints_v4(otrng_global_state_s *otrng_state);

void persistance_read_fingerprints_v4(otrng_global_state_s *otrng_state);

int persistance_write_fingerprints_v3(otrng_global_state_s *otrng_state);

void persistance_read_fingerprints_v3(otrng_global_state_s *otrng_state);

#endif
