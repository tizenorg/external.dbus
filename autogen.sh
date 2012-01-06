#!/bin/sh

aclocal -I m4
autoheader
autoconf
libtoolize --copy --automake
automake --add-missing --copy --gnu
./configure "$@"
