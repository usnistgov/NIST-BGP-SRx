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
 * cfgFile allows to generate a fully functional sample configuration file
 * for BGPsec-IO
 *
 * @version 0.2.1.4
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.1.4 - 2021/03/29 - oborchert
 *            * Changed naming from all uppercase to BGPsec-IO
 *  0.2.1.0 - 2017/12/20 - oborchert
 *            * Moved default defines into configuration.h
 *          - 2017/12/13 - oborchert
 *            * Modified the parameter list of generateFile.
 *          - 2017/12/11 - oborchert
 *            * Modified function generateFile and added interface name to 
 *              parameter list.
 *            * Added CFG_DEF_... defines.
 *  0.1.1.0 - 2016/04/29 - oborchert
 *            * Modified signature of function generateFile by removing the 
 *              program Parameters. The generated file is a sample configuration
 *              containing all possible settings.
 *            * Updated to reflect latest configuration settings.
 *  0.1.0.0 - 2015/11/29 - oborchert
 *            * Created File.
 */
#ifndef CFGFILE_H
#define	CFGFILE_H

#include <stdbool.h>
#include "configuration.h"

/**
 * Generate an example configuration file. In case no interface name "iface" is 
 * provided, the address used is CFG_DEF_IPV4 (10.0.1.64) otherwise the address 
 * bound to the interface.
 * 
 * @param fName The name of the configuration file.
 * @param iface The name of the local interface the file will be configured for.
 * @param localASN  The AS number of the local host (> 0).
 * @param peerIP The peer IP address (MUST NOT be NULL). 
 * @param peerASN The peer as number (> 0).
 * 
 * @return true if the file could be generated, false if no name was given or 
 *              the file already exists.
 */
bool generateFile(char* fName, char* iface, u_int32_t localASN, 
                  char* peerIP, u_int32_t peerASN);

#endif	/* CFGFILE_H */

