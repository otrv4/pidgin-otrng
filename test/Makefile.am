# 
#  Off-the-Record Messaging plugin for pidgin
#  Copyright (C) 2004-2018  Ian Goldberg, Rob Smits,
#                           Chris Alexander, Willy Lew,
#                           Nikita Borisov
#                           <otr@cypherpunks.ca>
#                           The pidgin-otrng contributors
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

check_PROGRAMS = test

test_SOURCES = 	test.c \
			    $(pidgin_otrng_la_SOURCES)

test_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)
test_LDFLAGS = $(pidgin_otrng_la_LDFLAGS) @TEST_LIBS@
