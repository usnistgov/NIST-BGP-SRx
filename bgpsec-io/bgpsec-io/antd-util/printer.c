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
 *             * Removed '\0' from format string. This caused warnings.
 *             * Reformatted Version Control.
 *   0.3.0.0 - 2016/04/16 - oborchert
 *             * added au_hexStrToBin which allows to copy hex strings into 
 *               binary buffers.
 *   0.2.0.0 - 2015/10/14 - oborchert
 *             * added au_print... functions
 *             * added prefix au_ to each method. au stands for antd-util.
 *   0.1.0.0 - 2015/09/09 - oborchert
 *             * Created File.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include "antd-util/printer.h"

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
char* au_binToHexString(u_int8_t* binBuff, int length, char* out)
{
  int len = length * 2 + 1;
  if (out == NULL)
  {
     out = malloc(len);
  }
  char* ptr = out;
  while (length > 0)
  {
    ptr += sprintf(ptr, "%02X", *binBuff);
    length--;
    binBuff++;
  }
  sprintf(ptr, "%c", '\0');
  
  return out;
}

/**
 * Convert the given hex byte into an unsigned byte.
 * 
 * @param hexByte the hex byte (2 characters)
 * 
 * @return the integer value. 
 */
u_int8_t au_hexToByte(char* hexByte)
{
  char hexBuf[5] = {'0', 'x', hexByte[0], hexByte[1], 0};  
  return (u_int8_t)strtol(hexBuf, NULL, 0);
}

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
 */
int au_hexStrToBin(char* hexStr, u_int8_t* buff, int buffSize)
{
  char* newStr = NULL;
  int strLen = strlen(hexStr);
  
  if (strLen % 2 > 0)
  {
    // left padd the string
    newStr = malloc(strLen + 2);
    snprintf(newStr, strLen + 1, "0%s", hexStr);
    hexStr = newStr;
    strLen++;
  }
  
  if ((buffSize * 2) < strLen)
  {
    // Shorten the string length to the buffer size,
    strLen = buffSize*2;    
  }
  
  int buffIdx = 0;
  while (strLen > 0)
  {
    buff[buffIdx++] = au_hexToByte(hexStr);
    hexStr += 2;
    strLen -= 2;
  }
  
  if (newStr != NULL)
  {
    free(newStr);
  }
  return buffIdx;
}


/**
 * Print the given hex string to the stdio.
 * 
 * @param binBuff The binary buffer
 * @param buffLen Length of the buffer
 * @param cr add CR at the end.
 */
void au_printBinToHexString(u_int8_t* binBuff, int buffLen, bool cr)
{
  char str[buffLen+1];
  au_binToHexString(binBuff, buffLen, str);
  if (cr)
  {
    printf ("%s\n", str);
  }
  else
  {
    printf ("%s", str);
  }
}

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
                     bool printEmptyLine)
{
  // "XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX" => 48 + 1
#define ALIGN_SIZE  49
#define ALIGN_USAGE 48
  char  fmtLine[ALIGN_SIZE]; // incl \0
  int   fmtPos  = 0;
  int   dataLen = strlen(dataStr);
  int   dataPos = 0;
  int   line    = 0;
  char* lineStr = NULL;
  
  while (dataPos < dataLen)
  {
    line++;
    memset (fmtLine, '\0', ALIGN_SIZE);
    fmtPos = 0;
    
    // Now fill the formated data line
    while (fmtPos < ALIGN_USAGE && dataPos < dataLen)
    {
      if ((dataPos % 16 == 0) && (dataPos % 32 > 0)) // 8 bytes
      { // Add the seconf blank as gap. between both blocks of 8
        fmtLine[fmtPos++] = ' ';
        fmtLine[fmtPos++] = ' ';
      } 
      else if (fmtPos > 0)
      {// Add a one blank gap between the bytes
        fmtLine[fmtPos++] = ' ';
      }

      fmtLine[fmtPos++] = dataStr[dataPos++];
      fmtLine[fmtPos++] = dataStr[dataPos++];
    }
    // Determine what to print 
    lineStr = line == 1 ? line1Fmt : line2Fmt;
    printf (lineStr, c1, fmtLine);
  }
  if (dataLen == 0)
  {
    // No data to print, but print first line.
    printf (line1Fmt, c1, "");
  }
}

#define AU_PRN_NORM 0
#define AU_PRN_INFO 1
#define AU_PRN_WARN 2
#define AU_PRN_ERR  3

/**
 * Will do the final printing of messages on stdio or stderr depending on the 
 * type.
 * 
 * @param type The type of printout (PRN_NORM|PRN_INFO|PRN_WARN|PRN_ERR)
 * @param format The format string
 * @param ... The parameters for the formated string.
 */
static void _au_printf(int type, const char *format, ...)
{
  char buffer[0xff] = {0};
  char *slevel = "";

  va_list ap;

  va_start(ap, format);
  vsnprintf( buffer, 0xff, format, ap);
  va_end(ap);

  switch (type)
  {
    case AU_PRN_WARN: 
      fprintf(stdout, "WARNING: %s", buffer);
      break;
    case AU_PRN_ERR:
      fprintf(stderr, "ERROR: %s", buffer);
      break;
    case AU_PRN_INFO:
      slevel = "INFO: ";
    default:
      fprintf(stdout, "%s%s", slevel, buffer);
  }
  //vsyslog((int)level, format, ap);
}

/**
 * Do a regular printout.
 * 
 * @param format The format string
 * @param ... The parameters for the formated string.
 */
void au_printf(const char *format, ...)
{
  va_list ap;
  _au_printf (AU_PRN_NORM, format, ap);
}

/**
 * Do an error printout.
 * @param format The formated string.
 * @param ... The parameters for the formated string.
 */
void au_printERR(char* format, ...)
{
  va_list ap;
  _au_printf (AU_PRN_ERR, format, ap);
}

/**
 * Do an info printout.
 * @param format The formated string.
 * @param ... The parameters for the formated string.
 */
void au_printWARN(char* format, ...)
{
  va_list ap;
  _au_printf (AU_PRN_WARN, format, ap);
}

/**
 * Do an info printout.
 * @param format The formated string.
 * @param ... The parameters for the formated string.
 */
void au_printINFO(char* format, ...)
{
  va_list ap;
  _au_printf (AU_PRN_INFO, format, ap);
}

