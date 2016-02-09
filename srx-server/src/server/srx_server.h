/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 * 
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 * 
 * We would appreciate acknowledgment if the software is used.
 * 
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 *
 * This file does provide CONSTANT declarations ONLY
 *
 * Version 0.3.1.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.1.0 - 2015/11/11 - oborchert
 *         * Fixed speller in program name from SRX to SRx
 * 0.3.0.7 - 2015/04/21 - oborchert
 *         * Modified Version numbering by referring specification to Makefile.
 * 0.3.0.0 - 2013/02/04 - oborchert
 *         * Added REVISION number that will be taken from the compiler using
 *           the compiler setting -DSRX_REVISION
 * 0.2.0.0 - 2011/05/24 - oborchert
 *         * File created
 * 
 */

#ifndef SRX_SERVER_H
#define	SRX_SERVER_H

// Some Macros to deal with the SRX_REVISION compiler parameter
#define SRX_STRINGIFY_ARG(ARG) " " #ARG
#define SRX_STRINGIFY_IND(ARG) SRX_STRINGIFY_ARG(ARG)

#define SRX_DO_CHECKVAL(VAL) VAL ## 1
#define SRX_CHECKVAL(VAL)    SRX_DO_CHECKVAL(VAL)


#define SRX_SERVER_NAME     "SRx Server"

#ifndef SRX_SERVER_PACKAGE
// Is provided by Makefile as CFLAGS -I
#define SRX_SERVER_PACKAGE  "NA"
#endif

// Compiler setting -D SRX_REVISION
#ifdef SRX_REVISION
  #if (SRX_CHECKVAL(SRX_REVISION) == 1)
    // SRX_REVISION is empty -> discard it
    #define SRX_SERVER_REVISION ""    
  #else
    #define SRX_SERVER_REVISION SRX_STRINGIFY_IND(SRX_REVISION)
  #endif
#else
  #define SRX_SERVER_REVISION ""
#endif

// Used version number -  make a string of the define
#define SRX_SERVER_VERSION  SRX_STRINGIFY_IND(SRX_SERVER_PACKAGE)
// Used full version number
#define SRX_SERVER_FULL_VER SRX_SERVER_VERSION SRX_SERVER_REVISION

#define SRX_CREDITS "This program was developed at the National Institute "  \
                "of Standards and Technology (NIST - www.nist.gov) in "      \
                "Gaithersburg, Maryland, U.S.A\r\n\r\n"                      \
                "Developers:\r\n"                                            \
                "------------------------------------------------------\r\n" \
                "  Oliver Borchert    (borchert@nist.gov) (2010-present)\r\n"  \
                "  Kyehwan Lee        (kyehwanl@nist.gov) (2011-present)\r\n"  \
                "  Patrick Gleichmann (pgleichm@nist.gov) (2010)\r\n"        \
                "------------------------------------------------------\r\n" \
                "\n"

#endif	/* SRX_SERVER_H */

