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
 * @version 0.2.1.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.0  - 2017/12/21 - oborchert
 *             * Added capability to add keys into an existing as list. Modified
 *               function preloadKeys.
 *           - 2017/10/12 - oborchert
 *             * Modified parameters of CAPI_createSignature
 *           - 2017/09/05 - oborchert
 *             * BZ1212, update code to be compatible with SCA 0.3.0
 *             * Added define CRYPTO_KEYSOURCE
 *  0.2.0.10 - 2017/09/01 - oborchert
 *             * Added CAPI_createSignature to header file.
 *             * Replaced static arrays nist_p256_rfc6979_A_2_5_SHA256_k_sample 
 *               and nist_p256_rfc6979_A_2_5_SHA256_k_test with appropriate
 *               defines and moved the array generation into the Crypto.c file.
 *  0.2.0.7  - 2017/03/22 - oborchert
 *             * Added K into the header.
 *             * Added function CRYPTO_k_to_string
 *  0.2.0.5  - 2017/01/03 - oborchert
 *             * Added function parameter "k_mode" to CRYPTO_createSignature.
 *  0.1.1.0  - 2016/03/28 - oborchert
 *             * Modified signature of preloadKeys to indicate what keys have to
 *               be loaded
 *           - 2016/03/22 - oborchert
 *             * Modified signature of function CRYPTO_createSignature by adding 
 *               the parameter testSig.
 *             * Removed not implemented function CRYTPO_release.
 *  0.1.0.0  - 2015/08/06 - oborchert
 *             * Created File.
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

/** Set an arbitrary key source */
#define CRYPTO_KEYSOURCE 1

/** The enumeration type for key types. */
typedef enum T_Key {
  k_private = 1,
  k_public  = 2,
  k_both    = 3  
} T_Key;

// Size of each k-array
#define CRYPTO_K_SIZE 32

/** k, RFC 6979 A2.5, SHA-256, message="sample" */
#define NIST_P256_RFC6979_A_2_5_SHA256_K_SAMPLE                 \
                0xA6, 0xE3, 0xC5, 0x7D, 0xD0, 0x1A, 0xBE, 0x90, \
                0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xDD, 0x4C, \
                0x3B, 0x17, 0xAA, 0x87, 0x33, 0x82, 0xB0, 0xF2, \
                0x4D, 0x61, 0x29, 0x49, 0x3D, 0x8A, 0xAD, 0x60

/** k, RFC 6979 A2.5, SHA-256, message="test" */
#define NIST_P256_RFC6979_A_2_5_SHA256_K_TEST                   \
                0xD1, 0x6B, 0x6A, 0xE8, 0x27, 0xF1, 0x71, 0x75, \
                0xE0, 0x40, 0x87, 0x1A, 0x1C, 0x7E, 0xC3, 0x50, \
                0x01, 0x92, 0xC4, 0xC9, 0x26, 0x77, 0x33, 0x6E, \
                0xC2, 0x53, 0x7A, 0xCA, 0xEE, 0x00, 0x08, 0xE0

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
 * @param k_mode  Specifies if a random k (preferred) or s specified k has to be 
 *                used.
 * 
 * @return 0 if the signature could not be generated, otherwise the length of 
 *         the signature in host format
 */
int CRYPTO_createSignature(TASList* asList, tPSegList* segElem, 
                           u_int8_t* message, int len, int algoID, bool testSig, 
                           SignatureGenMode k_mode);

/**
 * Read the given ASN-SKI file and generate an internal list containing all 
 * entries including the keys.
 * 
 * @param asList a preloaded as list that will receive more keys.
 * @param fileName The key-loader filename of the ASN-SKI list
 * @param keyRoot The root of the key files.
 * @param addEC_KEY if true the EC_KEY will be generated as well.
 * @param keytype indicated if the keys loaded are private, public or both keys
 * 
* @return the AS list with the keys or NULL if the keyloader ASN_SKI could not
 *         be found.
  */
TASList* preloadKeys(TASList* asList,
                     char* fileName, char* keyRoot, bool addEC_KEY, 
                     u_int8_t algoID, T_Key keytype);

/**
 * Print the K as hex strin ginto the given hex buffer.
 * this function returns false if the hex buffer was not large enough or if the 
 * given k type was invalid.
 * 
 * @param str_buff The buffer where k will be written into as string
 * @param buff_size The size of the buffer
 * @param k_mode the k that is selected
 * 
 * @return true if the selected k could be printed into the string.
 */
bool CRYPTO_k_to_string(char* str_buff, int buff_size, SignatureGenMode k_mode);

/**
 * Create the signature from the given hash for the ASN. The given signature 
 * must be NULL. The return value is the signature in a memory allocated into 
 * signature with the size given in the return value.
 * 
 * @param capi The SRxCryptoAPI
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
int CAPI_createSignature(SRxCryptoAPI* capi, TASList* asList, 
                         tPSegList* segElem, u_int8_t* message, int len, 
                         u_int8_t algoID, bool testSig);
#endif	/* CRYPTO_H */

