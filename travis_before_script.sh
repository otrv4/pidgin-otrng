#!/usr/bin/env bash

set -ex

mkdir -p .deps

GPG_ERROR_DIR=.deps/libgpg-error-1.26
LIBGCRYPT_DIR=.deps/libgcrypt-1.8.1
LIBSODIUM_DIR=.deps/libsodium-stable
LIBOTR_DIR=.deps/libotr
LIBGOLDILOCKS_DIR=.deps/libgoldilocks

export PREFIX=/tmp/prefix

if [[ -f $GPG_ERROR_DIR/src/.libs/libgpg-error.so ]]; then
    pushd $GPG_ERROR_DIR && make install && popd
else
    curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf - -C .deps
    pushd $GPG_ERROR_DIR && ./configure --prefix=$PREFIX && make && make install && popd
fi

if [[ -f $LIBGCRYPT_DIR/src/.libs/libgcrypt.so ]]; then
    pushd $LIBGCRYPT_DIR && make install && popd
else
    curl https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2 | tar xjf - -C .deps
    pushd $LIBGCRYPT_DIR && ./configure --with-libgpg-error-prefix=$PREFIX --prefix=$PREFIX && make && make install && popd
fi

if [[ -f $LIBSODIUM_DIR/src/libsodium/.libs/libsodium.so ]]; then
    pushd $LIBSODIUM_DIR && make install && popd
else
    curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf - -C .deps
    pushd $LIBSODIUM_DIR && ./autogen.sh && ./configure --prefix=$PREFIX && make && make install && popd
fi

if [[ -f $LIBOTR_DIR/src/.libs/libotr.so ]]; then
    pushd $LIBOTR_DIR && make install && popd
else
    git clone --depth=1 https://bugs.otr.im/lib/libotr.git $LIBOTR_DIR
    pushd $LIBOTR_DIR && ./bootstrap && ./configure --prefix=$PREFIX && make && make install && popd
fi

if [[ -f $LIBGOLDILOCKS_DIR/src/.libs/libgoldilocks.so ]]; then
    pushd $LIBGOLDILOCKS_DIR && make install && popd
else
    git clone --depth=1 https://github.com/otrv4/libgoldilocks $LIBGOLDILOCKS_DIR
    pushd $LIBGOLDILOCKS_DIR && ./autogen.sh && ./configure --prefix=$PREFIX && make && make install && popd
fi

if [[ ! -f .deps/pidgin.tar.bz2 ]]; then
    curl -L https://sourceforge.net/projects/pidgin/files/Pidgin/2.13.0/pidgin-2.13.0.tar.bz2/download > .deps/pidgin.tar.bz2
fi
tar xjf .deps/pidgin.tar.bz2 -C $PREFIX
