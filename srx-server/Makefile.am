ACLOCAL_AMFLAGS = -I m4
extrasdir =$(srcdir)/extras

EXTRA_DIST = $(extrasdir)/files $(extrasdir)/building.txt $(extrasdir)/make-lp.sh
SUBDIRS = src

#pkgincludedir = $(srcdir)
#nobase_pkginclude_HEADERS = $(extrasdir)/local/include/libconfig.h

#pkgincludedir = $(libdir)
#pkginclude_HEADERS = $(extrasdir)/local/lib/libconfig.a \
		     $(extrasdir)/local/lib/libconfig.so \
		     $(extrasdir)/local/lib/libconfig.so.9 \
		     $(extrasdir)/local/lib/libconfig.so.9.0.1\
		     $(extrasdir)/local/lib/libpatricia.a \
		     $(extrasdir)/local/lib/libpatricia.la \
		     $(extrasdir)/local/lib/libpatricia.so \
		     $(extrasdir)/local/lib/libpatricia.so.0 \
		     $(extrasdir)/local/lib/libpatricia.so.0.0.0

include_HEADERS = $(extrasdir)/local/include/libconfig.h \
		  $(extrasdir)/local/include/patricia.h \
		  $(extrasdir)/local/include/uthash.h 

dist_noinst_SCRIPTS = $(extrasdir)/make-lp.sh

#
#TODO: libpaticia.so & libpatricia.so.0 must be a linkage file
#

rpms srcrpm:
	for dir in $(SUBDIRS); do \
	    (cd $$dir $$ $(MAKE) $(AM_MAKEFLGAS) $@) || exit 1; \
	done


dist-hook:
	rm -rf `find $(distdir) -name .svn`

.PHONY: rpms srcrpm
