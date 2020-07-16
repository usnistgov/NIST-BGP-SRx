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
 * @version 0.2.1.0
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.1.0 - 2018/11/29 - oborchert
 *            * Removed merge comments in version control.
 *          - 2018/01/11 - oborchert
 *            * Modified function isUpdateStackEmpty to consider multi session
 *              update stacks.
 *          - 2018/01/10 - oborchert
 *            * Added TO DO statements for session stack handling where 
 *              appropriate.
 *  0.2.0.17- 2018/04/26 - oborchert
 *            * Added AS_SET to function convertAsnPath for 4byte ASN check.
 *  0.2.0.16- 2018/04/21 - oborchert
 *            * Removed incorrect adding of AS 0 to path when path consists of
 *              string containing only blanks.
 *  0.2.0.11- 2018/03/22 - oborchert
 *            * Added OUT parameter to function convertAsnPath
 *  0.2.0.10- 2017/09/01 - oborchert
 *            * Fixed compiler warning for un-used return value while using 
 *              fgets in isUpdateStackEmpty
 *  0.2.0.7 - 2017/05/03 - oborchert
 *            * BZ1122: Fixed problems with piped updates.
 *  0.2.0.2 - 2016/11/14 - oborchert
 *            * Fixed speller in documentation.
 *          - 2016/06/29 - oborchert
 *            * Fixed BZ995 segmentation failed during AS path conversion. 
 *              Replaced sprintf with snprintf in convertAsnPath.
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Assured that function convertAsnPath does return a zero 
 *              terminated string and not NULL.
 *  0.2.0.0 - 2016/05/10 - oborchert
 *            * Fixed compiler warnings BZ950
 *  0.1.1.0 - 2016/04/21 - oborchert
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
 * @param params The program parameters which include the stack
 * @param sessionNr Specify the number of the session whose updates are polled.
 *                  It is expected that global updates are added to the session
 *                  stack.
 * @param inclStdIn Include the check for stdin
 * 
 * @return true if an update is on the stack.
 */
bool isUpdateStackEmpty(PrgParams* params, int sessionNr, bool inclStdIn)
{
  Stack* updateStack = sessionNr < params->sessionCount
                       ? &params->sessionConf[sessionNr]->updateStack
                       : NULL;
  bool isEmpty = isStackEmpty(updateStack);
  
  if (isEmpty && inclStdIn)
  {
    char line[MAX_DATABUF];
    int lineLen = 0;
    if (_checkSTDIN(WAIT_FOR_STDIN_SEC, WAIT_FOR_STDIN_MSEC))
    {
      UpdateData* update = NULL;

      if (fgets(line, MAX_DATABUF, stdin) != NULL)
      {
        lineLen = strlen(line);
        if (lineLen != 0)
        {
          if (lineLen <= MAX_LINE_LEN)
          {
            if (line[lineLen-1] == '\n')
            {
              // Replace a possible CR with '\0'
              line[lineLen-1] = '\0';
              update = createUpdate(line, params);
              if (update != NULL)
              {
                pushStack(updateStack, update);
                isEmpty = false;
              }
            }
            else
            {
              printf("ERROR: Piped input is not closed with new line (\\n)- "
                     "drop input to prevent dead loop!!'\n");            
              printf ("   Line: '%s'\n", line);
            }
          }
          else
          {
            printf("ERROR: Piped input line exceeded maximum size of %i bytes.\n", 
                   MAX_LINE_LEN);
            printf ("   Line: '%s'\n", line);
          }
        }
      }
    }
  }
  
  return isEmpty;
}

/**
 * Converts a given path into either a compressed path or deflates a compressed 
 * path into its long string. It always returns a new string regardless of the
 * input. The length 0 string contains "\0".
 * The AS_SET will only be processed to determine if it contains 4Byte ASNs.
 * 
 * Compressed:   10p2 20 30p5
 * Decompressed: 10 10 20 30 30 30 30 30
 * 
 * @param path The path (can be NULL)
 * @param asSet The AS_SET if specified. (can be NULL)
 * @param hasAS4 (OUT) This bool pointer returns true if the given path contains
 *               4 byte AS numbers. (CAN BE NULL)
 * 
 * @return A new allocated, zero terminated string that needs to be free'd by 
 *         the caller.
 */
char* convertAsnPath(char* path, char* asSet, bool* has4ByteASN)
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
  
  bool contains4ByteASN = false;
  
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
          contains4ByteASN = true;
        }
        else
        {
          // Added this query to prevent adding as zero to the path.
          if (asn2 != 0)
          {
            snprintf(cASN, STR_MAX, "%d", asn2);
            if (asn2 > 0xFFFF)
            {
              contains4ByteASN = true;
            }
          }
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
        *cASN  = '\0';
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
  
  // Check AS_SET if it exists for 4 Byte AS numbers only if it is not found 
  // already.
  if ((asSet != NULL) && !contains4ByteASN)
  {
    char* tmpPath = convertAsnPath(asSet, NULL, &contains4ByteASN);
    free (tmpPath);
  }
  
  if (has4ByteASN != NULL)
  {
    *has4ByteASN = contains4ByteASN;
  }
  
  return retVal;
}
