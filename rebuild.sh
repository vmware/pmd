#!/bin/sh
make clean && make distclean
aclocal && libtoolize && automake --add-missing && autoreconf && ./configure --with-likewise=/opt/likewise --with-vmware-rest=/usr/lib/vmware-rest --enable-python=yes --enable-demo=yes
make
