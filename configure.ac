dnl Process this file with autoconf to produce configure.

AC_INIT(pidgin-otr, 3.1.0)

AM_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE([-Wall -Werror])

AC_PROG_CC

dnl We do not want to create a .a for the plugin, so disable by default.
AM_DISABLE_STATIC
AM_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1:1.2.0,,AC_MSG_ERROR(libgcrypt 1.2.0 or newer is required.))

AM_PATH_LIBOTR(3.1.0,,AC_MSG_ERROR(libotr 3.1.0 or newer is required.))

PKG_CHECK_MODULES([EXTRA], [glib-2.0 >= 2.6 gtk+-2.0 >= 2.6 pidgin >= 2.0 purple >= 2.0])

AC_PROG_INTLTOOL

GETTEXT_PACKAGE=pidgin-otr
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, ["$GETTEXT_PACKAGE"], [Define the gettext package to be used])

ALL_LINGUAS="es fr nl sk"
AM_GLIB_GNU_GETTEXT

AC_OUTPUT([Makefile po/Makefile.in])
