
SUBDIRS = lib doc

if BUILDEXAMPLES
SUBDIRS += examples
endif

.PHONY: dist-rpm

dist-rpm: distcheck
	rpmbuild -ta $(distdir).tar.gz


msvc7:
	find . -name '*\.vcproj' | grep -v '7' \
	| while read x; do \
		d=`dirname $$x`; \
		y=`basename $$x .vcproj`-msvc7.vcproj; \
		rm -f $$d/$$y; \
		perl -p -e 's/Version="8.00"/Version="7.10"/g' < $$x > $$d/$$y; \
	done; \
	rm -f libconfig-msvc7.sln libconfig-msvc7.sln.tmp; \
	perl -p -e 's/Version 9.00/Version 8.00/g' < libconfig.sln \
		> libconfig-msvc7.sln.tmp; \
	perl -p -e 's/\.vcproj/-msvc7.vcproj/g' \
		< libconfig-msvc7.sln.tmp > libconfig-msvc7.sln; \
	rm -f libconfig-msvc7.sln.tmp

EXTRA_DIST = \
	*.sln \
	test.cfg \
	TODO \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/docs \
	debian/libconfig++9-dev.install \
	debian/libconfig++9.install \
	debian/libconfig9-dev.docs \
	debian/libconfig9-dev.install \
	debian/libconfig9.info \
	debian/libconfig9.install \
	debian/rules \
	debian/shlibs \
	debian/watch \
	libconfig.spec
