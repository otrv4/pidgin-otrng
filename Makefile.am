AM_CFLAGS=	@LIBGCRYPT_CFLAGS@ @LIBOTR_CFLAGS@ @EXTRA_CFLAGS@
AM_CFLAGS+=	-DUSING_GTK -DGAIM_PLUGINS \
		-DGAIM_OTR_VERSION=\"@VERSION@\"

plugindir=		${libdir}/gaim

plugin_LTLIBRARIES=	gaim-otr.la

gaim_otr_la_SOURCES=		otr-plugin.c ui.c dialogs.c gtk-ui.c gtk-dialog.c
gaim_otr_la_LDFLAGS=		-module -avoid-version
gaim_otr_la_LDFLAGS+=	@LIBGCRYPT_LIBS@ @LIBOTR_LIBS@

EXTRA_DIST=		dialogs.h gtk-dialog.h gtk-ui.h otr-plugin.h ui.h \
			Makefile.mingw packaging
