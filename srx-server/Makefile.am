ACLOCAL_AMFLAGS = -I m4
extrasdir =$(srcdir)/extras
EXTRA_DIST = $(extrasdir)/files $(extrasdir)/make-lp.sh

SUBDIRS = src

dist_noinst_SCRIPTS = $(extrasdir)/make-lp.sh

# RPM script and macros for SRx
RPM = rpm

rpms srcrpm: all dist extra_dist
	for dir in $(SUBDIRS); do \
		(cd $$dir && $(MAKE) $(AM_MAKEFLAGS) $@) || exit 1; \
		rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
		test -z "$$dir/$$rpmarch" || ( mv $$dir/$$rpmarch/* . && rm -rf $$dir/$$rpmarch ); \
		rm -rf $$dir/$(distdir); \
	done
	rm -rf $(extrasdir)/files/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz
	mv src/*.rpm .
	



dist-hook:
	rm -rf `find $(distdir) -name .svn`

# for preparing rpm sources
extra_dist:
	cp -rf $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz $(extrasdir)/files/


distclean-local:
	rm -rf autom4te.cache $(extrasdir)/local \
	$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz $(PACKAGE_TARNAME)-*.rpm

.PHONY: rpms srcrpm
