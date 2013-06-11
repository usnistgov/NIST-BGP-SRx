ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = $(SRX_REVISION_FILE)

SUBDIRS = shared util client server tools
.PHONY: clean-local tags-local echo $(SUBDIRS)


# Extract the directory of this file out of the MAKEFILE_LIST
SRC_DIR=`pwd`

# Exuberant Ctags
READLINE_COPTS = -lreadline -lncurses
CLEAN_SUBDIRS	= .libs
LIBTOOL = libtool --tag=CC

# For the revision
SRX_VENDOR=antd.nist.gov
SVN_DIR = .svn
SVN_CMD = /usr/bin/svn

all-local: set-revision

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

set-revision:
	@echo "Check for revision framework"
	@touch $(SRX_REVISION_FILE);
	@if test -d $(SVN_DIR); then \
	  if test -f $(SVN_CMD); then \
	    $(SVN_CMD) info | grep $(SRX_VENDOR); \
	    if test "$$?" = "0"; then \
	      $(SVN_CMD) info | grep $(SRX_VENDOR); \
	      if test "$$?" = "0"; then \
		$(MAKE) set-revision-1; \
	      fi; \
	    fi; \
	  fi; \
	fi;
	
set-revision-1:
	@echo "Revision file=" $(SRX_REVISION_FILE)
	@echo -n $$($(SVN_CMD) info | grep Revision | sed -e "s/\(Revision:[ ]*\)\(.*\)\([ ]*\)/R\2-/g") > $(SRX_REVISION_FILE)
	@echo -n $$($(SVN_CMD) info | grep "Last Changed Rev" | sed -e "s/\(Last Changed Rev:[ ]*\)\(.*\)\([ ]*\)/LR\2/g") >> $(SRX_REVISION_FILE)
	@echo -n "Full-Version = $(VERSION)-"
	@cat $(SRX_REVISION_FILE)
	@echo
	@echo

