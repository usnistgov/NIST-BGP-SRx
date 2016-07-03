ACLOCAL_AMFLAGS = -I m4

.PHONY: distclean-local rpms srcrpm

SUBDIRS = antd-util $(CUNIT_TESTS)
CLEAN_SUBDIRS   = .libs .deps
EXTRA_DIST = $(PACKAGE_TARNAME).spec.in

distclean-local:
	rm -f *.spec; \
	rm -f bgpsecio-*.rpm; \
	rm -f bgpsecio-*.tar.gz; \
	rm -rf autom4te.cache;

bin_PROGRAMS = bgpsecio

bgpsecio_SOURCES = ASList.c \
                   ASNTokenizer.c \
                   updateStackUtil.c \
                   bgpsec/Crypto.c \
                   bgpsec/BGPSecPathBin.c \
		   bgp/BGPFinalStateMachine.c \
                   bgp/BGPHeader.c \
                   bgp/printer/BGPPrinterUtil.c \
                   bgp/printer/BGPUpdatePrinter.c \
                   bgp/printer/BGPNotificationPrinter.c \
                   bgp/printer/BGPHeaderPrinter.c \
                   bgp/BGPSession.c \
                   cfg/configuration.c \
                   cfg/cfgFile.c \
                   player/player.c \
                   bgpsecio.c


AM_FLAGS = -DPRG_VERSION=@MAJOR_VER@.@MINOR_VER@

bgpsecio_LDADD = $(top_srcdir)/antd-util/libantd_util.la

bgpsecio_CFLAGS = $(CFLAGS) $(OPENSSL_CFLAGS) $(SCA_CFLAGS)

bgpsecio_LDFLAGS = $(L_FLAGS) $(LIBS) $(SCA_LDFLAGS) $(OPENSSL_LDFLAGS)\
                   -ldl \
                   -lm \
                   -lrt \
                   -lconfig \
                   -lSRxCryptoAPI \
                   @OPENSSL_LIBS@
                   
################################################################################
##  RPM Section
################################################################################


# RPM script and macros for BGPSEC-IO
RPM = rpm

# RPM script and macros for BGPSEC-IO
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
	($(RPMBUILD) $(RPMFLAGS) -bs $(rpmmacros) $(rpmspec)) || exit 1

rpms: dist rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -ba $(rpmmacros) $(rpmspec)) || exit 1
	rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
	test -z "$$rpmarch" || ( mv $$rpmarch/* . && rm -rf $$rpmarch ); \
	rm -rf $(distdir)

dist-hook:
	rm -rf `find $(distdir) -name .svn`
