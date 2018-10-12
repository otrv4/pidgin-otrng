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

PIDGIN_TOP=../../..
AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR_CFLAGS@ @LIBOTRNG_CFLAGS@ @EXTRA_CFLAGS@ @LIBXML_CFLAGS@
AM_CFLAGS+=	-DUSING_GTK -DPURPLE_PLUGINS \
		-I$(PIDGIN_TOP)/libpurple \
		-I$(PIDGIN_TOP)/pidgin \
		-DPIDGIN_OTR_VERSION=\"@VERSION@\" \
		-DLOCALEDIR=\"$(datadir)/locale\"

SUBDIRS=	po test

plugindir=		${libdir}/pidgin

plugin_LTLIBRARIES=	pidgin-otrng.la

pidgin_otrng_la_SOURCES 	= otrng-plugin.c \
				  prekey-plugin.c \
				  prekey-plugin-peers.c \
				  prekey-plugin-account.c \
				  prekey-plugin-shared.c \
				  prekey-discovery.c \
				  prekey-discovery-jabber.c \
				  prekeys.c \
				  plugin-all.c \
				  plugin-conversation.c \
				  ui.c \
				  dialogs.c \
				  gtk-ui.c \
				  gtk-dialog.c \
				  tooltipmenu.c \
				  otrng-client.c \
				  long_term_keys.c \
				  fingerprint.c \
                  pidgin-helpers.c \
                  persistance.c \
				  profiles.c

pidgin_otrng_la_LDFLAGS=	-module -avoid-version
pidgin_otrng_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR_LIBS@ @LIBOTRNG_LIBS@

#TODO: Make sure windows packaging works
EXTRA_DIST=		dialogs.h gtk-dialog.h gtk-ui.h otr-plugin.h ui.h \
			otr-icons.h tooltipmenu.h prekey-discovery.h prekey-discovery-jabber.h \
			Makefile.mingw packaging/windows/pidgin-otr.nsi \
			packaging/fedora/pidgin-otr.spec po/Makefile.mingw \
			po/README intltool-extract.in intltool-merge.in \
			intltool-update.in Makefile.static INSTALL.mingw

DISTCLEANFILES=		intltool-extract intltool-merge intltool-update

code-style:
	clang-format -style=file -i config.h *.h *.c

test: check
	test/test
