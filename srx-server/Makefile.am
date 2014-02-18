ACLOCAL_AMFLAGS = -I m4
extrasdir =$(srcdir)/extras
EXTRA_DIST = $(extrasdir)/files $(extrasdir)/make-lp.sh

SUBDIRS = src

#pkgincludedir = $(srcdir)
#nobase_pkginclude_HEADERS = $(extrasdir)/local/include/libconfig.h

dist_noinst_HEADERS = $(extrasdir)/local/include/libconfig.h
include_HEADERS = $(extrasdir)/local/include/patricia.h \
				  $(extrasdir)/local/include/uthash.h


dist_noinst_SCRIPTS = $(extrasdir)/make-lp.sh

#
#TODO: libpaticia.so & libpatricia.so.0 must be a linkage file
#

#rpms srcrpm:
#	for dir in $(SUBDIRS); do \
#	    (cd $$dir $$ $(MAKE) $(AM_MAKEFLGAS) $@) || exit 1; \
#	done

# RPM script and macros for SRx
RPM = rpm

rpms srcrpm: dist extra_dist
	for dir in $(SUBDIRS); do \
		(cd $$dir && $(MAKE) $(AM_MAKEFLAGS) $@) || exit 1; \
		rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
		test -z "$$dir/$$rpmarch" || ( mv $$dir/$$rpmarch/* . && rm -rf $$dir/$$rpmarch ); \
		rm -rf $$dir/$(distdir); \
	done
	rm -rf $(extrasdir)/files/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz
	



dist-hook:
	rm -rf `find $(distdir) -name .svn`

# for preparing rpm sources
extra_dist:
	cp -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz $(extrasdir)/files/


.PHONY: rpms srcrpm
