
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @BGPSEC_OPENSSL@ @CRYPTO_TESTLIB@
DIST_SUBDIRS = @BGPSEC_OPENSSL@ @CRYPTO_TESTLIB@

EXTRA_DIST = $(PACKAGE_TARNAME).spec.in \
             srxcryptoapi_lib$(CPU_ARCH).conf

.PHONY: distclean-local rpmcheck srcrpm rpms $(SUBDIRS)

CLEAN_SUBDIRS	= .libs .deps

# Add the configuration directory as compiler setting to allow finding the 
# location of the configuration file.
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" @MCHECK@
AM_CFLAGS = @CFLAGS@  @OPENSSL_CFLAGS@
AM_LDFLAGS = @LDFLAGS@ @OPENSSL_LDFLAGS@

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else 
  LIB_VER = 0:0:0
endif

# Used to generate the srx folder for installation - DESTDIR for RPM generation
INC_OUT = $(DESTDIR)$(includedir)/$(SRX_DIR)

# SRxCryptoAPI Library
pkglib_LTLIBRARIES = libSRxCryptoAPI.la 
pkglibdir = $(libdir)

libSRxCryptoAPI_libconfigdir = $(sysconfdir)/ld.so.conf.d
dist_libSRxCryptoAPI_libconfig_DATA = srxcryptoapi_lib$(CPU_ARCH).conf

libSRxCryptoAPI_la_SOURCES = srxcryptoapi.c \
                             crypto_imple.c
 
libSRxCryptoAPI_la_LDFLAGS = -version-info $(LIB_VER) $(OPENSSL_LDFLAGS)

# this follwing line for Ubuntu x86_64
libSRxCryptoAPI_la_LIBADD = $(OPENSSL_LIBS)

noinst_HEADERS  = srx/srxcryptoapi.h crypto_imple.h

# Crypto Key generation tools
dist_sbin_SCRIPTS = tools/qsrx-make-cert tools/qsrx-make-key \
	tools/qsrx-publish tools/qsrx-view-cert \
	tools/qsrx-view-csr tools/qsrx-view-subject

# Configuration files
dist_sysconf_DATA = srxcryptoapi.conf.sample \
                    tools/qsrx-router-key.cnf.sample


# SRxCryptoAPI Test program
sbin_PROGRAMS = srx_crypto_tester

srx_crypto_tester_LDFLAGS = $(L_FLAGS) $(LIBS) -ldl $(OPENSSL_LDFLAGS) @OPENSSL_LIBS@
srx_crypto_tester_SOURCES = srx_api_test.c
srx_crypto_tester_CFLAGS = @CFLAGS@ $(OPENSSL_CFLAGS)
srx_crypto_tester_LDADD = $(top_srcdir)/libSRxCryptoAPI.la

distclean-local:
	rm -f srxcryptoapi-*.spec; \
	rm -f srxcryptoapi-*.rpm; \
	rm -f srxcryptoapi-*.tar.gz; \
	rm -rf autom4te.cache; \
	rm srxcryptoapi_lib*.conf

install-exec-local:
	@if [ ! -d $(INC_OUT) ]; then \
	  mkdir -p $(INC_OUT); \
	fi
	@echo "Copying srxcryptoapi.h"
	cp -f srx/srxcryptoapi.h $(INC_OUT)/srxcryptoapi.h
		
uninstall-local:
	rm -f $(INC_OUT)/srxcryptoapi.h;
	@if [ -e $(INC_OUT) && "@DOLLAR_SIGN@(ls -A $(INC_OUT))" == "" ] ; then \
	  rmdir $(INC_OUT) > /dev/null 2>&1; \
	fi

################################################################################
##  RPM Section
################################################################################


# RPM script and macros for SRx
RPM = rpm

# RPM script and macros for SRx
rpmspec = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).spec

rpmmacros =\
 --define="_rpmdir $${PWD}"\
 --define="_srcrpmdir $${PWD}"\
 --define="_sourcedir $${PWD}"\
 --define="_specdir $${PWD}"\
 --define="_builddir $${PWD}"

RPMBUILD = rpmbuild
RPMFLAGS = --nodeps --buildroot="$${PWD}/_rpm"

rpmcheck:
	if [ which rpmbuild &> /dev/null ]; then \
	 echo "*** This make target requires an rpm-based linux distribution."; \
	(exit 1); exit 1; \
	fi

srcrpm: rpmcheck $(rpmspec)
	$(RPMBUILD) $(RPMFLAGS) -bs $(rpmmacros) $(rpmspec)

rpms: dist rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -ba $(rpmmacros) $(rpmspec)) || exit 1
	rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
	test -z "$$rpmarch" || ( mv $$rpmarch/* . && rm -rf $$rpmarch ); \
	rm -rf $(distdir)

