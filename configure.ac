dnl Process this file with autoconf to produce configure.

dnl XXX Check for headers, etc.

dnl Not yet used.
AC_INIT(otr-plugin.c)

AM_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE(gaim-otr, 3.0.0)

AC_PROG_CC

dnl We do not want to create a .a for the plugin, so disable by default.
AM_DISABLE_STATIC
AM_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1:1.2.0,,AC_MSG_ERROR(libgcrypt 1.2.0 or newer is required.))

AM_PATH_LIBOTR(3.0.0,,AC_MSG_ERROR(libotr 3.0.0 or newer is required.))

PKG_CHECK_MODULES(EXTRA, glib-2.0 >= 2.4 gtk+-2.0 >= 2.4 gaim >= 1.0, , AC_MSG_ERROR(glib, gtk and gaim required))

AC_OUTPUT([Makefile])
