#!/bin/sh
make clean && make distclean
aclocal && libtoolize && automake --add-missing && autoreconf && ./configure --with-likewise=/opt/likewise --with-vmdirclient=/opt/vmware --with-vmafdclient=/opt/vmware --enable-rpcprivsep=no
make
