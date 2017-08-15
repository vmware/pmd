ACLOCAL_AMFLAGS = -I m4

APP_NAME=pmd
CLEANFILES =
EXTRA_DIST =
conf_DATA = conf/pmd.conf
pkginclude_HEADERS = include/pmd.h include/pmdtypes.h include/pmderror.h
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = \
    idl \
    common \
    jsonutils \
    client \
    server \
    tools

if ENABLE_PYTHON
    SUBDIRS += python
endif

pkgconfig_DATA = pmdclient.pc
pmdclient.pc: $(top_srcdir)/pmdclient.pc.in
	./config.status --file=${subdir}/pmdclient.pc:${subdir}/pmdclient.pc.in
CLEANFILES += pmdclient.pc
EXTRA_DIST += pmdclient.pc.in

tar-src:
	git archive --format=tar.gz --prefix=$(APP_NAME)-$(VERSION)/ -o $(APP_NAME)-$(VERSION).tar.gz HEAD

rpm: tar-src
	mkdir -p .rpm/SOURCES
	mkdir -p .rpm/BUILD
	mkdir -p .rpm/RPMS/x86_64
	-rm -rf .rpm/RPMS/$(APP_NAME)-*
	-rm -rf .rpm/SOURCES/$(APP_NAME)-*
	mv $(APP_NAME)-$(VERSION).tar.gz .rpm/SOURCES
	rpmbuild --quiet --nodeps --define="_topdir $(abs_top_builddir)/.rpm" \
	-bb $(APP_NAME).spec
	mkdir -p rpms
	mv .rpm/RPMS/x86_64/$(APP_NAME)-*$(VERSION)-*.x86_64.rpm rpms

clean-local:
	-rm -rf .rpm
	-rm -rf rpms