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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/05/25 -pgleichm
 *            * Code created. 
 */

#include <stdarg.h>
#include "util/xml_out.h"

void initXMLOut(XMLOut* self, FILE* stream) 
{
  self->stream  = stream;
  self->level   = 0;
  self->open    = false;

  initSList(&self->tagStack);

  fprintf(stream, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
}

void releaseXMLOut(XMLOut* self) 
{
  if (self != NULL) 
  {
    releaseSList(&self->tagStack);
  }
}

void openTag(XMLOut* self, const char* name) 
{
  if (self->open) 
  {
    fprintf(self->stream, ">\n");
  }

  if (insertDataIntoSList(&self->tagStack, 0, (void*)name)) 
  {
    if (self->level == 0) 
    {
      fprintf(self->stream, "<%s", name);
    } 
    else 
    {
      fprintf(self->stream, "%*c<%s", self->level, ' ', name);
    }

    self->open = true;
    self->level += 2;
  } 
  else 
  {
    fprintf(self->stream, "<!-- Error while opening '%s' -->", name);
    self->open = false;
  }
}

void closeTag(XMLOut* self) 
{
  const char* name;

  name = shiftFromSList(&self->tagStack);
  if (name != NULL) 
  {
    self->level -= 2;
  } 
  else 
  {
    name = "?";
  }

  if (self->open) 
  {
    fprintf(self->stream, " />\n");
    self->open = false;
  } 
  else if (self->level > 0) 
  {
    fprintf(self->stream, "%*c</%s>\n", self->level, ' ', name);
  } 
  else 
  {
    fprintf(self->stream, "</%s>\n", name);
  }
}

void addAttrib(XMLOut* self, const char* name, const char* fmt, ...) 
{
  va_list ap;

  fprintf(self->stream, " %s=\"", name);
  va_start(ap, fmt);
  vfprintf(self->stream, fmt, ap);
  va_end(ap);
  fputc('"', self->stream);
}

inline void addStrAttrib(XMLOut* self, const char* name, const char* str) 
{
  fprintf(self->stream, " %s=\"%s\"", name, str);
}

void addBoolAttrib(XMLOut* self, const char* name, bool flag) 
{
  fprintf(self->stream, " %s=\"%s\"", name, (flag ? "yes" : "no"));
}

inline void addIntAttrib(XMLOut* self, const char* name, int value) 
{
  fprintf(self->stream, " %s=\"%d\"", name, value);
}

inline void addU32Attrib(XMLOut* self, const char* name, uint32_t value) 
{
  fprintf(self->stream, " %s=\"%u\"", name, value);
}

/**
 * Adds a 32-bit integer attribute in hex format to the current XML tag.
 *
 * @param self Instance
 * @param name Attribute name
 * @param value Integer value
 */
void addH32Attrib(XMLOut* self, const char* name, uint32_t value)
{
  fprintf(self->stream, " %s=\"0x%08X\"", name, value);
}

