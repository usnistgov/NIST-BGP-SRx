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
 * by thsi software.
 *
 */
/**
 * @file math.h
 * @date Created: 05/06/2010
 *
 * Mathematical utility functions.
 */

#ifndef __MATH_H__
#define __MATH_H__

/**
 * Returns the larger value of two given values.
 *
 * @param A Value A
 * @param B Value B
 * @return Larger value
 */
#define MAX(A,B) ((A >= B) ? A : B)

/**
 * Returns the smaller value of two given values.
 *
 * @param A Value A
 * @param B Value B
 * @return Smaller value
 */
#define MIN(A,B) ((A <= B) ? A : B)

/**
 * Checks if a value lies within given boundaries.
 *
 * @param X Value
 * @param L Left border
 * @param R Right border
 * @return \c true = yes, \c false = no
 */
#define BETWEEN(X, L, R) \
  ((X >= L) && (X <= R))


#endif // !__MATH_H__

