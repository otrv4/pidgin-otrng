# Installation instructions

## Requirements

To compile the OTR plugin for pidgin, you'll need:

* [libgpg-error](ftp://ftp.gnupg.org/gcrypt/libgpg-error/)
* [libgcrypt](ftp://ftp.gnupg.org/gcrypt/libgcrypt/)
* [libotr 4.x](https://otr.cypherpunks.ca/)
* libsodium-dev
* libgoldilocks
* libotr-ng
* [libglib-dev](http://www.gtk.org/download/)
* [gtk+ 2.6](http://www.gtk.org/download/)
* [pidgin 2.x](http://pidgin.im/)

You'll also need the usual autotools, such as automake-1.9, autoreconf, libtool,
intltool, etc.

If you install these with a package manager, you'll probably need the -dev or
-devel versions of the packages.

## Compiling (non-Win32)

If you're got a git copy, you will need to regenerate the configure script using:

```
intltoolize --force --copy
autoreconf -s -i
```

(If you installed libotr.m4 somewhere that autoreconf can't find it, you can try
putting `ACLOCAL_FLAGS= -I /path/to/share/aclocal` at the top of Makefile.am.)

(If you are using Mac OSX 10.3.x or higher, you need to install `gettext` and
link it -`brew link --force gettext` to make the autoreconf command work)

Once you have the configure script (which comes with the source distribution),
run it with any options that may be necessary for your system.  Some examples:

```
Linux:
    ./configure --prefix=/usr --mandir=/usr/share/man

NETBSD:
    CPPFLAGS="-I/usr/pkg/include" LDFLAGS="-R/usr/pkg/lib -L/usr/pkg/lib" \
	./configure --prefix=/usr/pkg
```

(If you are using Mac OSX, you might run into this error:
`XML::Parser perl module is required for intltool`. To solve it, run:
`perl -e shell -MCPAN` and then `install XML::Parser`)

Once the configure script writes a Makefile, you should be able to just
run `make`.

If you want a plugin that has libgcrypt linked statically, use
`make -f Makefile.static`. Makefile.static assumes all the dependencies are
statically linked and available in `/usr/lib`.

You can use these environment variables to change these locations:

```
  LIBOTRDIR
  LIBGCRYPTDIR
  LIBGPGERRORDIR
  LIBOTRNGDIR
  LIBGOLDILOCKSDIR
  LIBSODIUMDIR
```

Notice that each one of these libraries have to be compiled statically, and with
Position Independent Code. For all these libraries, you can achieve that by
calling `configure` with `--enable-state --with-pic`.

## Compiling (Win32)

Use the provided Makefile.mingw:

```
make -f Makefile.mingw
```

See INSTALL.mingw for a script to try to do everything for you, including all of
the dependencies.

## Installation

You should be able to simply do `make install`.  If you want to install
somewhere other than `/` (this is useful for package creators), use something
like `make DESTDIR=/path/to/install/to install`.
