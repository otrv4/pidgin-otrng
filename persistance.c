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
  g_free(filename);
  return f;
}

int persistance_write_privkey_v4_FILEp(otrng_global_state_s *otrng_state) {
  FILE *privf;
  gchar *privkeyfile =
      g_build_filename(purple_user_dir(), PRIVKEY_FILE_NAME_V4, NULL);
  if (!privkeyfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return -1;
  }

  privf = open_file_write_mode(privkeyfile);

  if (!privf) {
    fprintf(stderr, _("Could not write private key file\n"));
    return -1;
  }

  int err = 0;
  if (otrng_failed(
          otrng_global_state_private_key_v4_write_to(otrng_state, privf))) {
    err = -1;
  }
  fclose(privf);

  return err;
}

void persistance_read_private_keys_v4(otrng_global_state_s *otrng_state) {
  gchar *f = g_build_filename(purple_user_dir(), PRIVKEY_FILE_NAME_V4, NULL);
  if (!f) {
    return;
  }

  FILE *fp = g_fopen(f, "rb");
  g_free(f);

  otrng_global_state_private_key_v4_read_from(
      otrng_state, fp, protocol_and_account_to_purple_conversation);

  if (fp) {
    fclose(fp);
  }
}

int persistance_write_client_profile_FILEp(otrng_global_state_s *otrng_state) {
  FILE *f;

  gchar *file_name =
      g_build_filename(purple_user_dir(), CLIENT_PROFILE_FILE_NAME, NULL);
  if (!file_name) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return -1;
  }
  f = open_file_write_mode(file_name);

  if (!f) {
    fprintf(stderr, _("Could not write client profile file\n"));
    return -1;
  }

  int err = 0;
  if (otrng_failed(
          otrng_global_state_client_profile_write_to(otrng_state, f))) {
    err = -1;
  }
  fclose(f);

  return err;
}

void persistance_read_client_profile(otrng_global_state_s *otrng_state) {
  gchar *f =
      g_build_filename(purple_user_dir(), CLIENT_PROFILE_FILE_NAME, NULL);
  if (!f) {
    return;
  }

  FILE *fp = g_fopen(f, "rb");
  g_free(f);

  otrng_global_state_client_profile_read_from(
      otrng_state, fp, protocol_and_account_to_purple_conversation);

  if (fp) {
    fclose(fp);
  }
}
