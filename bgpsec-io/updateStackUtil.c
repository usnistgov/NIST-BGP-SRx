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
 * This class Uses the Stack.h stack but also adds some IO functionality for
 * bgpsecio. It provides a function isUpdateStackEmpty which checks first the
 * stack but if the stack is empty it checks if another update might be waiting
 * on the stdin pipe. In this case it generates an update, adds it to the stack
 * and returns true, otherwise it returns false.
 * 
 * The reverse mode might be possible in future updates.
 * 
 * @version 0.2.0.2
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.2 - 2016/06/29 - oborchert
 *            * Fixed BZ995 segmentation failt during AS path conversion. 
 *              Replaced sprintf with snprintf in convertAsnPath.
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Assured that function convertAsnPath does return a zero 
 *              terminated string and not NULL.
 *  0.2.0.0 - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *  0.1.1.0 - 2016/04/21 - borchert
 *            * Added parameter inclStdIn for speedup
 *           - 2016/04/20 - borchert
 *            * Created File.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "updateStackUtil.h"
#include "bgp/printer/BGPHeaderPrinter.h"

/**
 * Poll the standard input to see if something is waiting on the standard in.
 * 
 * @param sec seconds to wait
 * @param msec milli seconds to wait
 * 
 * @return true if data is ready, otherwise false.
 */
static bool _checkSTDIN(int sec, int msec)
{
  bool ready = false;
    // Check std in
  fd_set rfds;
  struct timeval tv;
  int    retVal;
  
  FD_ZERO(&rfds);
  FD_SET(0, &rfds);
  
  tv.tv_sec  = sec;
  tv.tv_usec = msec;
  
  retVal = select(1, &rfds, NULL, NULL, &tv);
  
  if (retVal == -1)
  {
    perror("select()");
  }
  else if (retVal != 0)
  {
    ready = true;
  }

  return ready;
}

/**
 * This method checks if the given stack is empty. In case it is empty it checks
 * if updates are waiting on stdin if selected (inclStdIn). In this case the 
 * next update will be generated and added to the stack.
 *  
 * @param params The program parameters which in clude the stack
 * @param inclStdIn Include the check for stdin
 * 
 * @return true if an update is on the stack.
 */
bool isUpdateStackEmpty(PrgParams* params, bool inclStdIn)
{
  bool isEmpty = isStackEmpty(&params->updateStack);
  if (isEmpty && inclStdIn)
  {
    char line[MAX_DATABUF];
    int lineLen = 0;
    if (_checkSTDIN(WAIT_FOR_STDIN_SEC, WAIT_FOR_STDIN_MSEC))
    {
      UpdateData* update = NULL;

      fgets(line, MAX_DATABUF, stdin);
      lineLen = strlen(line);
      if (lineLen != 0)
      {
        if (line[lineLen-1] == '\n')
        {
          line[lineLen-1] = '\0';
          update = createUpdate(line, params);
          if (update != NULL)
          {
            pushStack(&params->updateStack, update);
            isEmpty = false;
          }
        }
        else
        {
          printf("ERROR: Input line exceeded maximum size of %i bytes.\n", 
                 MAX_DATABUF);
          printf ("Line: %s\n", line);
        }
      }
    }
  }
  
  return isEmpty;
}

/**
 * Converts a given path into either a compressed path or deflates a compressed 
 * path into its long string. It always returns a new string regardless of the
 * input. The length 0 string contains "\0" 
 * 
 * Compressed:   10p2 20 30p5
 * Decompressed: 10 10 20 30 30 30 30 30
 * 
 * @param path The path (can be NULL)
 * 
 * @return A new allocated, zero terminated string that needs to be free'd by 
 *         the caller.
 */
char* convertAsnPath(char* path)
{
  char       cASN[STR_MAX];
  char*      retVal  = NULL;
  char*      ptr     = path;
  int        pathLen = strlen(path); 
  int        strSize = 0;
  u_int32_t  asn1    = 0; // the upper asn;
  u_int32_t  asn2    = 0; // the lower asn;
  u_int32_t  pCount  = 0;
  u_int32_t* val     = &asn2;
  
  int  idx;
  bool store   = false;
  memset (cASN, '\0', STR_MAX);
 
  if (path != NULL)
  {
    if (strcmp("p", path) == -1)
    {
      strSize = strlen(path) + 1;
      retVal = malloc(strSize);
      snprintf(retVal, strSize, "%s", path);
      pathLen = 0;
    }
    
    while (pathLen != 0)
    {
      switch ((char)*ptr)
      {
        case '0' ... '9':
          *val = (*val * 10) + ((char)*ptr - '0');
          break;
        case '.':
          asn1 = asn2;
          asn2 = 0;
          break;
        case 'p':
        case 'P':
          pCount = 0;
          val = &pCount;
          break;          
        case ' ':
        case '\t':
        case '\n':
        default:
          store = asn1+asn2 > 0;
          break;
      }
      pathLen--;
      ptr++;
            
      // Either more ASN's are in the loop or the last was read - in both 
      // cases store the ASN
      if (store || pathLen == 0)
      {
        // If pCount was not set, set it to 1
        pCount = (val == &pCount) ? pCount : 1;        
        if (asn1 != 0)
        {
          snprintf(cASN, STR_MAX, "%d.%d", asn1, asn2);
        }
        else
        {
          snprintf(cASN, STR_MAX, "%d", asn2);
        }
        // Now use the pCount setting to repeat the ASN
        for (idx = 1; idx <= pCount; idx++)
        {
          if (retVal != NULL)
          {            
            // Fixed segmentation fault BZ 995 - issues with realloc. This is 
            // not the most efficient fix but it works, can be made better at a
            // later time.
            strSize = strlen(retVal) + strlen(cASN) + 2;
            char* newStr = malloc(strSize);
            snprintf(newStr, strSize, "%s %s", retVal, cASN);
            free(retVal);
            retVal = NULL;
            retVal = newStr;
            newStr = NULL;
          }
          else
          {
            strSize = strlen(cASN) + 1;
            retVal = malloc(strSize);
            snprintf(retVal, strSize, "%s", cASN);
          }
        }
        
        // switch val back to read the ASN
        val    = &asn2;
        asn2   = 0;
        asn1   = 0;
        pCount = 0;
        store = false;        
      }
    }
  }
  
  if (retVal == NULL)
  {
    retVal  = malloc(1);
    *retVal = '\0';
  }
  return retVal;
}