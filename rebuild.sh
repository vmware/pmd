#!/bin/sh
make clean && make distclean
aclocal && libtoolize && automake --add-missing && autoreconf && ./configure --with-likewise=/opt/likewise --enable-python=yes --enable-demo=yes
make
