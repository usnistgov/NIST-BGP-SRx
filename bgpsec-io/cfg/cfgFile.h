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
 * for BGPSEC-IO
 *
 * @version 1.1.0
 *  
 * Changelog:
 * -----------------------------------------------------------------------------
 *  0.1.1.0 - 2016/04/29 - 0borchert
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
 * Generate the configuration file.
 * 
 * @param fName The name of the configuration file.
 * 
 * @return true if the file could be written!
 */
bool generateFile(char* fName);

#endif	/* CFGFILE_H */

