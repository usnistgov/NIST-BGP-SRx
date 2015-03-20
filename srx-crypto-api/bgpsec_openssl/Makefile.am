
ACLOCAL_AMFLAGS = -I m4

CFLAGS = @CFLAGS@ -I.  @OPENSSL_CFLAGS@

CLEAN_SUBDIRS	= .libs .deps

lib_LTLIBRARIES = libSRxBGPSecOpenSSL.la
libSRxBGPSecOpenSSL_la_SOURCES = bgpsec_openssl.c
libSRxBGPSecOpenSSL_la_LIBADD = @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else
  LIB_VER = 0:0:0
endif

libSRxBGPSecOpenSSL_la_LDFLAGS = -version-info $(LIB_VER) -module #-avoid-version

include_HEADERS = bgpsec_openssl.h

