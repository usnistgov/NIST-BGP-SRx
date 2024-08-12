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
                   bgp/printer/BGPOpenPrinter.c \
                   bgp/printer/BGPHeaderPrinter.c \
                   bgp/BGPSession.c \
                   cfg/configuration.c \
                   cfg/cfgFile.c \
                   player/player.c \
                   bgpsecio.c

noinst_HEADERS = \
                   player/player.h \
                   updateStackUtil.h \
                   ASList.h          \
                   cfg/cfgFile.h     \
                   cfg/configuration.h  \
                   ASNTokenizer.h       \
                   bgpsec/Crypto.h      \
                   bgpsec/BGPSecPathBin.h  \
                   bgp/BGPHeader.h         \
                   bgp/printer/BGPNotificationPrinter.h \
                   bgp/printer/BGPHeaderPrinter.h       \
                   bgp/printer/BGPPrinterUtil.h         \
                   bgp/printer/BGPOpenPrinter.h         \
                   bgp/printer/BGPUpdatePrinter.h       \
                   bgp/BGPSession.h                     \
                   bgp/BGPFinalStateMachine.h           \
                   config.h                             \
                   antd-util/printer.h                  \
                   antd-util/prefix.h                   \
                   antd-util/linked_list.h              \
                   antd-util/log.h                      \
                   antd-util/stack.h

# Crypto Key generation tools
dist_bin_SCRIPTS = tools/bio-traffic.sh \
                   tools/mrt_to_bio.sh

AM_FLAGS = -DPRG_VERSION=@MAJOR_VER@.@MINOR_VER@

bgpsecio_LDADD = $(top_srcdir)/antd-util/libantd_util.la

#bgpsecio_CFLAGS = $(CFLAGS) $(SCA_CFLAGS) $(OPENSSL_CFLAGS)
bgpsecio_CFLAGS = $(SCA_CFLAGS) $(OPENSSL_CFLAGS) $(OS_CFLAGS)

bgpsecio_LDFLAGS = $(LDFLAGS) $(SCA_LDFLAGS) $(OPENSSL_LDFLAGS)\
                   -ldl \
                   -lm \
                   -lrt \
                   -lconfig \
                   @OPENSSL_LIBS@ \
                   $(SCA_LIBS) \
                   $(LIBS)

################################################################################
##  RPM Section
################################################################################


# RPM script and macros for BGPsec-IO
RPM = rpm

# RPM script and macros for BGPsec-IO
rpmspec = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).spec

rpmmacros =\
 --define="_rpmdir $${PWD}"\
 --define="_srcrpmdir $${PWD}"\
 --define="_sourcedir $${PWD}"\
 --define="_specdir $${PWD}"\
 --define="_builddir $${PWD}"

RPMBUILD = rpmbuild
#RPMFLAGS = --nodeps --buildroot="$${PWD}/_rpm"
RPMFLAGS = --buildroot="$${PWD}/_rpm"

rpmcheck:
	if [ which rpmbuild &> /dev/null ]; then \
	 echo "*** This make target requires an rpm-based linux distribution."; \
	(exit 1); exit 1; \
	fi

srcrpm: rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -bs $(rpmmacros) $(rpmspec)) || exit 1

rpms: dist rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -bb $(rpmmacros) $(rpmspec)) || exit 1
	rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
	test -z "$$rpmarch" || ( mv $$rpmarch/* . && rm -rf $$rpmarch ); \
	rm -rf $(distdir)

dist-hook:
	rm -rf `find $(distdir) -name .svn`
