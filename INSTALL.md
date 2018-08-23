# Requirements

To compile the OTR plugin for pidgin, you'll need at least:

- [libgpg-error 1.0](ftp://ftp.gnupg.org/gcrypt/libgpg-error/)
- [libgcrypt 1.2.0](ftp://ftp.gnupg.org/gcrypt/libgcrypt/)
- [libotr-ng](https://github.com/otrv4/libotr-ng)
- [glib 2.6](http://www.gtk.org/download/)
- [gtk+ 2.6](http://www.gtk.org/download/)
- [pidgin 2.x](http://pidgin.im/)

You'll also need the usual autotools, such as `automake`, `autoreconf`,
`libtool` and `intltool`.

If you install these with a package manager, you'll need the
`-dev` or `-devel` versions of the packages.

## Installing the requirements on Deiban/Ubuntu systems

    sudo apt install build-essential automake autoconf libtool intltool libgpg-error-dev libgcrypt20-dev libglib2.0-dev libgtk-3-dev pidgin-dev

### Install libotr-ng

First, install [libgoldilocks](https://github.com/otrv4/libgoldilocks) as a
dependency of `libotr-ng`

    git clone https://github.com/otrv4/libgoldilocks
    cd libgoldilocks
    ./autogen.sh && ./configure && make && sudo make install

Then install `libotr-ng` itself

    git clone https://github.com/otrv4/libotr-ng
    cd libotr-ng
    ./autogen.sh && ./configure && make && sudo make install


# Building the plugin

## Linux

    git clone https://github.com/otrv4/pidgin-otrng.git
    cd pidgin-otrng
    ./autogen.sh

Until prekey server discovery is implemented you need to pass the prekey server to test
as a compiler flag

    CC="gcc" CFLAGS="-ggdb3 -O0 -DDEFAULT_PREKEYS_SERVER='\"prekey.YOUR.XMPP.DOMAIN\"'" ./configure


## NetBSD

    CPPFLAGS="-I/usr/pkg/include" LDFLAGS="-R/usr/pkg/lib -L/usr/pkg/lib" \
	./configure --prefix=/usr/pkg

Once the configure script writes a Makefile, you should be able to just
run

    make

If you want a plugin that has libgcrypt linked statically, use
`make -f Makefile.static`. `Makefile.static` assumes `libotr.a` and `libgcrypt.a`
are available in `/usr/lib`.  If they're somewhere else, use something like
`LIBOTRDIR=/usr/local/lib make -f Makefile.static`.


## Windows

Use the provided Makefile.mingw:

    make -f Makefile.mingw

See `INSTALL.mingw` for a script to try to do everything for you,
including all of the dependencies.

# Installing the plugin

    make install

If you want to install somewhere other than `/` (this is useful
for package creators), use something like

    make DESTDIR=/path/to/install/to install

# Make plugin available to pidgin

Link the built plugin files to your `~/.purple/plugins` directory

    ln -s /usr/local/lib/pidgin/pidgin-otrng.la ~/.purple/plugins/pidgin-otrng.la
    ln -s /usr/local/lib/pidgin/pidgin-otrng.so ~/.purple/plugins/pidgin-otrng.so
