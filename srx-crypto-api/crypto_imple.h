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
 * This file provides the implementation for SRxCryptoAPI for loading OpenSSL 
 * generated keys. This package provides the qsrx_... scripts for key 
 * generation.
 * 
 * Known Issue:
 *   At this time only pem formated private keys can be loaded.
 * 
 * @version 0.1.2.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.1.2.0  - 2015/12/03 - oborchert
 *             * moved location of srxcryptoapi.h
 *           - September 23, 2015 - borchert
 *              * Created File from C file.
 *              * Modified and added data types.
 */
#ifndef CRYPTO_IMPLE_H
#define	CRYPTO_IMPLE_H

#include <openssl/obj_mac.h>
#include "srx/srxcryptoapi.h"

#define API_LOADKEY_SUCCESS  1
#define API_LOADKEY_FAILURE  0

#define CURVE_ECDSA_P_256 NID_X9_62_prime256v1


#define PRIVKEY_SIZE     32
#define SIZE_DER_PUBKEY  (0x59+2)

/**
 * Load the key from the key volt location configured within the API. The key
 * needs the SKI specified in binary format.
 * The returned key is in DER format. The parameter fPrivate is used to
 * indicate if the private or public key will be returned. This is of importance
 * in case both keys exist. Both keys will have the same SKI.
 *
 * @param key Pre-allocated memory where the ley will be loaded into.
 * @param fPrivate indicates if the key is private or public.
 * @param fileExt The extension of the filename containing the key.
 *
 * @return LOAD_KEY_SUCCESS (1) if key was loaded successfully, 
 *         LOAD_KEY_FAILURE (0) otherwise
 */
int impl_loadKey(BGPSecKey* key, bool fPrivate, char* fileExt);

#endif	/* CRYPTO_IMPLE_H */