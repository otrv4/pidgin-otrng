AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR_CFLAGS@ @EXTRA_CFLAGS@
AM_CFLAGS+=	-DUSING_GTK -DPURPLE_PLUGINS \
		-DPIDGIN_OTR_VERSION=\"@VERSION@\" \
		-DLOCALEDIR=\"$(datadir)/locale\"

SUBDIRS=	po

plugindir=		${libdir}/pidgin

plugin_LTLIBRARIES=	pidgin-otr.la

pidgin_otr_la_SOURCES=	otr-plugin.c ui.c dialogs.c gtk-ui.c gtk-dialog.c
pidgin_otr_la_LDFLAGS=	-module -avoid-version
pidgin_otr_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR_LIBS@

EXTRA_DIST=		dialogs.h gtk-dialog.h gtk-ui.h otr-plugin.h ui.h \
			Makefile.mingw packaging/windows/pidgin-otr.nsi \
			packaging/fedora/pidgin-otr.spec po/Makefile.mingw \
			po/README intltool-extract.in intltool-merge.in \
			intltool-update.in Makefile.static

DISTCLEANFILES=		intltool-extract intltool-merge intltool-update
