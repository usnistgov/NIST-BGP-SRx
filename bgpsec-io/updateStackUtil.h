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
 * This class Uses the Stack.h stack but also adds some IO functionality for
 * bgpsecio. It provides a function isUpdateStackEmpty which checks first the
 * stack but if the stack is empty it checks if another update might be waiting
 * on the stdin pipe. In this case it generates an update, adds it to the stack
 * and returns true, otherwise it returns false.
 * 
 * The reverse mode might be possible in future updates.
 * 
 * @version 0.2.0.1
 * 
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.2.0.1 - 2016/06/24 - oborchert
 *            * Assured that function convertAsnPath does return a zero 
 *              terminated string and not NULL.
 *  0.1.1.0 - 2016/04/21 - borchert
 *            * Added parameter inclStdIn for speedup
 *          - 2016/04/20 - borchert
 *            * Created File.
 */
#ifndef UPDATESTACKUTIL_H
#define	UPDATESTACKUTIL_H

#include <stdbool.h>
#include "cfg/configuration.h"

#define WAIT_FOR_STDIN_SEC  1
#define WAIT_FOR_STDIN_MSEC 1

/** A precaution to prevent segmentation faults. */
#define MAX_DATABUF 10000

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
bool isUpdateStackEmpty(PrgParams* params, bool inclStdIn);

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
char* convertAsnPath(char* path);

#endif	/* UPDATESTACKUTIL_H */

