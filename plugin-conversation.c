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

#include <stdint.h>
#include <stdlib.h>

#include <glib.h>

#include "plugin-conversation.h"

otrng_plugin_conversation *otrng_plugin_conversation_new(const char *account,
                                                         const char *protocol,
                                                         const char *peer) {
  otrng_plugin_conversation *ret = malloc(sizeof(otrng_plugin_conversation));
  if (!ret) {
    return ret;
  }

  ret->account = g_strdup(account);
  ret->protocol = g_strdup(protocol);
  ret->peer = g_strdup(peer);
  ret->their_instance_tag = 0;
  ret->our_instance_tag = 0;

  return ret;
}
