
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @BGPSEC_OPENSSL@ @CRYPTO_TESTLIB@
DIST_SUBDIRS = @BGPSEC_OPENSSL@ @CRYPTO_TESTLIB@
EXTRA_DIST = $(PACKAGE_TARNAME).spec.in

.PHONY: clean-local tags-local install-exec-hook echo $(SUBDIRS)


tags-local:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir tags; \
	done

clean-local: 
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

echo:
	for dir in $(SUBDIRS); do \
		(cd $$dir && $(MAKE) $(AM_MAKESET) $@ ); \
	done

CLEAN_SUBDIRS	= .libs .deps

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


# Add the configuration directory as compiler setting to allow finding the 
# location of the configuration file.
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" @MCHECK@
CFLAGS = @CFLAGS@  @OPENSSL_CFLAGS@
LDFLAGS = @LDFLAGS@ @OPENSSL_LDFLAGS@

# SRxCryptoAPI Library

lib_LTLIBRARIES = libSRxCryptoAPI.la
libSRxCryptoAPI_la_SOURCES = srxcryptoapi.c
if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else 
  LIB_VER = 0:0:0
endif
libSRxCryptoAPI_la_LDFLAGS = -version-info $(LIB_VER)


include_HEADERS = srxcryptoapi.h
#srxcrypto_configdir = $(sysconfdir)
#dist_srxcrypto_config_SCRIPTS = srxcryptoapi.conf.sample

# SRxCryptoAPI Test program

crypto_PROGRAMS = srx_crypto_tester
cryptodir=$(bindir)

srx_crypto_tester_LDFLAGS = $(L_FLAGS) $(LIBS) -ldl @OPENSSL_LIBS@
srx_crypto_tester_SOURCES = srx_api_test.c

if BGPSEC_OPENSSL_COND
  LTDL_BGPSEC_OPENSSL= $(BGPSEC_OPENSSL)/libSRxBGPSecOpenSSL.la
  LTDL_FLAGS = -dlopen
endif

srx_crypto_tester_LDADD = $(top_srcdir)/libSRxCryptoAPI.la  \
                          $(LTDL_FLAGS) $(LTDL_BGPSEC_OPENSSL) @OPENSSL_LIBS@

# Crypto Key generation tools

dist_sbin_SCRIPTS = tools/qsrx-make-cert tools/qsrx-make-key \
	tools/qsrx-publish tools/qsrx-view-cert \
	tools/qsrx-view-csr tools/qsrx-view-subject

# Configuration files
dist_sysconf_DATA = srxcryptoapi.conf.sample \
                    tools/qsrx-router-key.cnf.sample
