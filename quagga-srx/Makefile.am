## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ @BABELD@ \
         @ISISD@ @WATCHQUAGGA@ @VTYSH@ @OSPFCLIENT@ @DOC@ m4 @pkgsrcdir@ \
         redhat @SOLARIS@ @BUILD_TESTS@

DIST_SUBDIRS = lib zebra bgpd ripd ripngd ospfd ospf6d babeld \
	  isisd watchquagga vtysh ospfclient doc m4 pkgsrc redhat tests \
	  solaris

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS INSTALL.quagga.txt \
	update-autotools \
	INSTALL.SRx_client.txt \
	vtysh/Makefile.in vtysh/Makefile.am \
	tools/mrlg.cgi tools/rrcheck.pl tools/rrlookup.pl tools/zc.pl \
	tools/zebra.el tools/multiple-bgpd.sh \
	fpm/fpm.h 

ACLOCAL_AMFLAGS = -I m4

.PHONY: distclean-local clean-local rpms srcrpm

if HAVE_LATEX

HACKING.pdf: HACKING.tex
	$(LATEXMK) -pdf $<

clean-local:
	-$(LATEXMK) -C HACKING.tex

endif

distclean-local:
	rm -f quaggasrx-*.rpm quaggasrx-*.spec quaggasrx-*.tar.gz; \
	rm -rf autom4te.cache

# RPM script and macros for QuaggaSRx
RPM = rpm

#rpms srcrpm: dist extra_dist
#	for dir in $(SUBDIRS); do \
#,...,...(cd $$dir && $(MAKE) $(AM_MAKEFLAGS) $@) || exit 1; \
#,...,...rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
#,...,...test -z "$$dir/$$rpmarch" || ( mv $$dir/$$rpmarch/* . && rm -rf $$dir/$$rpmarch ); \
#,...,...rm -rf $$dir/$(distdir); \
#,...done


# RPM script and macros for SRx
#rpmspec = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).spec
rpmspec = redhat/quagga.spec

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

srcrpm: dist rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -bs $(rpmmacros) $(rpmspec)) || exit 1

rpms: dist rpmcheck $(rpmspec)
	($(RPMBUILD) $(RPMFLAGS) -ba $(rpmmacros) $(rpmspec)) || exit 1
	rpmarch=`$(RPM) --showrc | grep "^build arch" | sed 's/\(.*: \)\(.*\)/\2/'`; \
	test -z "$$rpmarch" || ( mv $$rpmarch/* . && rm -rf $$rpmarch ); \
	rm -rf $(distdir)

dist-hook:
	rm -rf `find $(distdir) -name .svn`


# for preparing rpm sources
#extra_dist:
