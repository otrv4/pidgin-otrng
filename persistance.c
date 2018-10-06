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

#include <libotr-ng/messaging.h>

#include "persistance.h"
#include "pidgin-helpers.h"

#include <libotr-ng/debug.h>

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

static FILE *open_file_write_mode(gchar *filename) {
  FILE *f;
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */

#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */

  f = g_fopen(filename, "w+b");

#ifndef WIN32
  umask(mask);
#endif /* WIN32 */

  return f;
}

#define PERSISTANCE_READ(filename, fn)                                         \
  do {                                                                         \
    gchar *f = g_build_filename(purple_user_dir(), filename, NULL);            \
    if (!f) {                                                                  \
      return;                                                                  \
    }                                                                          \
                                                                               \
    FILE *fp = g_fopen(f, "rb");                                               \
    g_free(f);                                                                 \
                                                                               \
    if (fp) {                                                                  \
      fn(otrng_state, fp, protocol_and_account_to_purple_conversation);        \
      fclose(fp);                                                              \
    }                                                                          \
  } while (0);

#define PERSISTANCE_WRITE(filename, fn)                                        \
  do {                                                                         \
    FILE *fp;                                                                  \
    int err = 0;                                                               \
    gchar *f = g_build_filename(purple_user_dir(), filename, NULL);            \
    if (!f) {                                                                  \
      return -1;                                                               \
    }                                                                          \
                                                                               \
    fp = open_file_write_mode(f);                                              \
    g_free(f);                                                                 \
                                                                               \
    if (otrng_failed(fn(otrng_state, fp))) {                                   \
      err = -1;                                                                \
    }                                                                          \
    if (fp) {                                                                  \
      fclose(fp);                                                              \
    }                                                                          \
                                                                               \
    return err;                                                                \
  } while (0);

int persistance_write_privkey_v4_FILEp(otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(PRIVKEY_FILE_NAME_V4,
                    otrng_global_state_private_key_v4_write_to);
}

void persistance_read_private_keys_v4(otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(PRIVKEY_FILE_NAME_V4,
                   otrng_global_state_private_key_v4_read_from);
}

int persistance_write_client_profile_FILEp(otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(CLIENT_PROFILE_FILE_NAME,
                    otrng_global_state_client_profile_write_to);
}

void persistance_read_client_profile(otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(CLIENT_PROFILE_FILE_NAME,
                   otrng_global_state_client_profile_read_from);
}

int persistance_write_prekey_profile_FILEp(otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(PREKEY_PROFILE_FILE_NAME,
                    otrng_global_state_prekey_profile_write_to);
}

void persistance_read_prekey_profile(otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(PREKEY_PROFILE_FILE_NAME,
                   otrng_global_state_prekey_profile_read_from);
}

int persistance_write_prekey_messages(otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(PREKEYS_FILE_NAME,
                    otrng_global_state_prekey_messages_write_to);
}

void persistance_read_prekey_messages(otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(PREKEYS_FILE_NAME, otrng_global_state_prekeys_read_from);
}

int persistance_write_forging_key(otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(FORGING_KEY_FILE_NAME,
                    otrng_global_state_forging_key_write_to);
}

void persistance_read_forging_key(otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(FORGING_KEY_FILE_NAME,
                   otrng_global_state_forging_key_read_from);
}

int persistance_write_expired_client_profile(
    otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(EXP_CLIENT_PROFILE_FILE_NAME,
                    otrng_global_state_expired_client_profile_write_to);
}

void persistance_read_expired_client_profile(
    otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(EXP_CLIENT_PROFILE_FILE_NAME,
                   otrng_global_state_expired_client_profile_read_from);
}

int persistance_write_expired_prekey_profile(
    otrng_global_state_s *otrng_state) {
  PERSISTANCE_WRITE(EXP_PREKEY_PROFILE_FILE_NAME,
                    otrng_global_state_expired_prekey_profile_write_to);
}

void persistance_read_expired_prekey_profile(
    otrng_global_state_s *otrng_state) {
  PERSISTANCE_READ(EXP_PREKEY_PROFILE_FILE_NAME,
                   otrng_global_state_expired_prekey_profile_read_from);
}
