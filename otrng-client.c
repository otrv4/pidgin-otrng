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

#include <stdio.h>

#include <libotr-ng/client.h>

#include "otrng-client.h"

char *otrv4_client_adapter_privkey_fingerprint(const otrng_client_s *client) {
  char *ret = NULL;

  otrng_fingerprint our_fp = {0};
  if (otrng_failed(otrng_client_get_our_fingerprint(our_fp, client))) {
    return NULL;
  }

  ret = malloc(OTRNG_FPRINT_HUMAN_LEN);
  if (!ret) {
    return NULL;
  }

  otrng_fingerprint_hash_to_human(ret, our_fp, sizeof(our_fp));
  return ret;
}
