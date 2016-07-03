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
 * This utility provides printing functions into character strings or screen
 * 
 * @version 0.3.0.1
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *   0.3.0.1 - 2016/05/10 - oborchert
 *             * Elevated function au_hexToByte into header file.
 *             * Reformatted Version Control.
 *   0.3.0.0 - 2016/04/19 - oborchert
 *             * added au_hexStrToBin which allows to copy hex strings into 
 *               binary buffers.
 *   0.2.0.0 - 2015/10/14 - oborchert
 *             * added au_print... functions
 *             * added prefix au_ to each method. au stands for antd-util.
 *   0.1.0.0 - 2015/09/09 - oborchert
 *             * Created File.
 */
#ifndef PRINTER_H
#define	PRINTER_H

#include <sys/types.h>
#include <stdbool.h>

/**
 * convert the binary stream into a hex string. The memory is allocated and 
 * MUST be freed by the caller.
 * 
 * @param binBuff the buffer
 * @param length the length of the buffer
 * @param out the out buffer (must be large enough - 2 x length+1) or NULL.
 * 
 * @return the allocated memory for the hex string if out is NULL, otherwise out  
 */
char* au_binToHexString(u_int8_t* binBuff, int length, char* out);

/**
 * Convert the hex string into the binary buffer. This function returns the 
 * number of bytes written into the binary buffer. In case the hex string is
 * un-even it will be padded at the front. the stream 1230 with result in 0x12
 * and 0x30 whereas the stream 123 will result in 0x01 0x23.
 * In case the buffer is not large enough, only the leading 'buffersize' bytes 
 * will be written.
 * 
 * @param hexStr The hex string that will be converted..
 * @param buff The byte buffer
 * @param buffSize The maximum capacity of the buffer
 * 
 * @return the number of bytes written into the buffer.
 * 
 * @since 0.3.0.0
 */
int au_hexStrToBin(char* hexStr, u_int8_t* buff, int buffSize);

/**
 * Convert the given hex byte into an unsigned byte.
 * 
 * @param hexByte the hex byte (2 characters)
 * 
 * @return the integer value. 
 * 
 * @since 0.3.0.1 in header file
 */
u_int8_t au_hexToByte(char* hexByte);

/**
 * Print the given hex string to the stdio.
 * 
 * @param binBuff The binary buffer
 * @param buffLen Length of the buffer
 * @param cr add CR at the end.
 */
void au_printBinToHexString(u_int8_t* binBuff, int buffLen, bool cr);

/**
 * Generate an aligned formated Hex string string.
 * 
 * @param line1Fmt The format of the first line. 
 * @param line2Fmt The format for the sencond+ line(s).
 * @param c1 The leading character
 * @param dataStr The string that contains the data in Hex format
 * @param printEmptyLine in case dataString is empty print the first line if
 *                       true
 * 
 */
void au_printHexAligned(char* line1Fmt, char* line2Fmt, char* c1, char* dataStr, 
                     bool printEmptyLine);

/**
 * Do a regular printout.
 * 
 * @param format The format string
 * @param ... The parameters for the formated string.
 */
void au_printf(const char *format, ...);

/**
 * Do an error printout.
 * @param format The formated string.
 * @param ... The parameters for the formated string.
 */
void au_printERR(char* format, ...);

/**
 * Do an info printout.
 * @param format The formated string.
 * @param ... The parameters for the formated string.
 */
void au_printWARN(char* format, ...);

#endif	/* PRINTER_H */