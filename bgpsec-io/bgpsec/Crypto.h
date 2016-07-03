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
 *
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * A wrapper for the OpenSSL crypto needed. It also includes a key storage.
 *
 * @version 0.1.1.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.1.1.0 - 2016/03/28 - oborchert
 *            * Modified signature of preloadKeys to indicate what keys have to
 *              be loaded
 *          - 2016/03/22 - oborchert
 *            * Modified signature of function CRYPTO_createSignature by adding 
 *              the parameter testSig.
 *            * Removed not implemented function CRYTPO_release.
 *  0.1.0.0 - 2015/08/06 - oborchert
 *            * Created File.
 */
#ifndef CRYPTO_H
#define	CRYPTO_H

#ifdef SCA_LDFLAG
#include "srx/srxcryptoapi.h"
#else
#include <srx/srxcryptoapi.h>
#endif
#include "bgpsec/BGPSecPathBin.h"
#include "ASList.h"

#define BGPSEC_MAX_SIG_LENGTH 128

/** The enumeration type for key types. */
typedef enum T_Key {
  k_private = 1,
  k_public  = 2,
  k_both    = 3  
} T_Key;

/**
 * Create the signature from the given hash for the ASN. The given signature 
 * must be NULL. The return value is the signature in a memory allocated into 
 * signature with the size given in the return value.
 * 
 * @param asList The list of as numbers - Contains all keys etc.
 * @param segElem The signature element where the signature will be stored in.
 * @param message The buffer containing the message to be signed.
 * @param len The length of the message in host format.
 * @param algoID  Specifies the algorithm to be used for signing.
 * @param testSig If true the generated signature is validated right away. This
 *                is for test purpose only.
 * 
 * @return 0 if the signature could not be generated, otherwise the length of 
 *         the signature in host format
 */
int CRYPTO_createSignature(TASList* asList, tPSegList* segElem, 
                          u_int8_t* message, int len, int algoID, bool testSig);

/**
 * Read the given ASN-SKI file and generate an internal list containing all 
 * entries including the keys.
 * 
 * @param fileName The key-loader filename of the ASN-SKI list
 * @param keyRoot The root of the key files.
 * @param addEC_KEY if true the EC_KEY will be generated as well.
 * @param keytype indicated if the keys loaded are private, public or both keys
 * 
* @return the AS list with the keys or NULL if the keyloader ASN_SKI could not
 *         be found.
  */
TASList* preloadKeys(char* fileName, char* keyRoot, bool addEC_KEY, 
                     u_int8_t algoID, T_Key keytype);
#endif	/* CRYPTO_H */

