
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = @CFLAGS@ -I.  @OPENSSL_CFLAGS@

CLEAN_SUBDIRS	= .libs .deps

if LIB_VER_INFO_COND
  LIB_VER = $(LIB_VER_INFO)
else
  LIB_VER = 0:0:0
endif

lib_LTLIBRARIES = libSRxBGPSecOpenSSL.la

libSRxBGPSecOpenSSL_la_SOURCES = bgpsec_openssl.c key_storage.c
libSRxBGPSecOpenSSL_la_LIBADD = @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@
libSRxBGPSecOpenSSL_la_LDFLAGS = -version-info $(LIB_VER) -module #-avoid-version

noinst_HEADERS = key_storage.h