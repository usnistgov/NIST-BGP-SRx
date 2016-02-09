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
 * Added last method (HEX) 
 * A primitive collection of functions to create XML output.
 *
 * Example:
 * @code
 * XMLOut out;
 *
 * initXMLOut(&out, stdout);
 * openTag(&out, "root")
 *  openTag(&out, "child");
 *    addIntAttrib(&out, "id", 123);
 *    addStrAttrib(&out, "name", "child-a");
 *  closeTag(&out);
 *  :
 * closeTag();
 * releaseXMLOut(&out);
 * @endcode
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2010/05/25 - pgleichm
 *            * Code created. 
 */

#ifndef __XML_OUT_H__
#define __XML_OUT_H__

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "util/slist.h"

/**
 * A single XML Out(put) instance.
 *
 * @note Do not modify
 */
typedef struct {
  // Argument
  FILE* stream;

  // Internal
  int   level;
  SList tagStack;
  bool  open;
} XMLOut;

/**
 * Initializes the XML Out.
 *
 * @param self Variable that should be initialized
 * @param stream The XML will be written to this output stream
 */
void initXMLOut(XMLOut* self, FILE* stream);

/**
 * Frees all allocated resources.
 *
 * @param self Instance
 */
void releaseXMLOut(XMLOut* self);

/**
 * Opens an XML tag.
 *
 * @note Use closeTag to close the tag
 *
 * @param self Instance
 * @param name Name of the tag
 */
void openTag(XMLOut* self, const char* name);

/**
 * Closes an XML tag.
 *
 * @param self Instance
 * @see openTag
 */
void closeTag(XMLOut* self);

/**
 * Adds an attribute to the current XML tag.
 *
 * Example:
 * @code
 * addAttrib(&out, "number", "%1.4f", afloat);
 * @endcode
 *
 * @param self Instance
 * @param name Attribute name
 * @param fmt printf Format
 * @param ... Single argument
 */
void addAttrib(XMLOut* self, const char* name, const char* fmt, ...);    

/**
 * Adds a string attribute to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param str String value
 */
void addStrAttrib(XMLOut* self, const char* name, const char* str);

/**
 * Adds a boolean attribute to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param flag \c true / \c false
 */
void addBoolAttrib(XMLOut* self, const char* name, bool flag);

/**
 * Adds an integer attribute to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param value Integer value
 */
void addIntAttrib(XMLOut* self, const char* name, int value);

/**
 * Adds an unsigned 32-bit integer attribute to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param value Integer value
 */
void addU32Attrib(XMLOut* self, const char* name, uint32_t value);

/**
 * Adds a 32-bit integer attribute in hex format to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param value Integer value
 */
void addH32Attrib(XMLOut* self, const char* name, uint32_t value);
#endif // !__XML_OUT_H__

