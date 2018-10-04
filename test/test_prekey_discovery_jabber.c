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

#include <glib.h>
#include <string.h>
#include <stdio.h>

char *get_domain_from_jid(const char *jid);

void test_get_domain_from_jid(void) {
  g_assert_cmpstr(get_domain_from_jid("ola@example.org/foo"), ==, "example.org");
  g_assert_cmpstr(get_domain_from_jid("example2.org/foo"), ==, "example2.org");
  g_assert_cmpstr(get_domain_from_jid("ola@example3.org"), ==, "example3.org");
  g_assert_cmpstr(get_domain_from_jid("ola@example4.org/"), ==, "example4.org");
  g_assert_cmpstr(get_domain_from_jid("example5.org"), ==, "example5.org");
  g_assert_cmpstr(get_domain_from_jid("ola@/foo"), ==, "");
  g_assert_cmpstr(get_domain_from_jid(""), ==, "");
  char *res1 = get_domain_from_jid(NULL);
  g_assert(res1 == NULL);
}
