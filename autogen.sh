#!/bin/sh

set -e

intltoolize --force --copy
autoreconf -s -i