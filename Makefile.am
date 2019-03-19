ACLOCAL_AMFLAGS = -I m4

APP_NAME=pmd
CLEANFILES =
EXTRA_DIST =
noinst_DATA =
conf_DATA = conf/pmd.conf
pkginclude_HEADERS = include/pmd.h include/pmdtypes.h include/pmderror.h include/roleplugin.h
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = \
    idl \
    common \
    jsonutils \
    client \
    server \
    privsep \
    tools

if ENABLE_PYTHON
    SUBDIRS += python
endif

noinst_DATA += pmd.spec
pmd.spec: $(top_srcdir)/pmd.spec.in
	./config.status --file=${subdir}/pmd.spec:${subdir}/pmd.spec.in
CLEANFILES += pmd.spec
EXTRA_DIST += pmd.spec.in

pkgconfig_DATA = pmdclient.pc
pmdclient.pc: $(top_srcdir)/pmdclient.pc.in
	./config.status --file=${subdir}/pmdclient.pc:${subdir}/pmdclient.pc.in
CLEANFILES += pmdclient.pc
EXTRA_DIST += pmdclient.pc.in

tar-src:
	git archive --format=tar.gz --prefix=$(APP_NAME)-$(VERSION)/ -o $(APP_NAME)-$(VERSION).tar.gz HEAD

rpm: tar-src pmd.spec
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
