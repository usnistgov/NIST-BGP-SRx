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
 * Dynamically loaded code.
 *
 * @note '-ldl' is required for the linker on Linux
 *
 * A typical plugin sceleton:
 * @code
 * #include "util/types.h"
 *
 * uint16_t getPluginVersion() { return 102; }
 * const char* getPluginDescription() { return "Example - description"; }
 *
 * void functionA(int value) {
 *   :
 * }
 * @endcode
 *
 * The corresponding code to load the plugin:
 * @code
 * const char* fnames = { "functionA", NULL };
 * struct { void (*functionA)(int value); } funcs;
 * const char* text;
 * void* handle;
 * :
 * handle = loadPlugin("plugin", 101, fnames, STRUCT_FUNC_PTRS(funcs), &text);
 * if (handle) {
 *    funcs.functionA(123);
 *    unloadPlugin(handle);
 * }
 * @endcode
 * 
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Removed types.h
 *            * Added Changelog
 * 0.1.0.0  - 2010/01/15 - pgleichm
 *            * Code created. 
 */
// @TODO: Check if still needed or if it can be deleted.
#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <stdint.h>

/*
 * Must be implemented - the initial letter should be lower-case
 */

/** 
 * The (required) implementation should return the current plugin version.
 *
 * @return Version number
 */
typedef uint16_t (*GetPluginVersion)();

/**
 * The (required) implementation should returned a description of the plugin.
 *
 * @return Descriptive text
 */ 
typedef const char* (*GetPluginDescription)();

/**
 * Use this macro to typecast the passed function-pointer struct.
 *
 * @param S Function-pointer struct
 */
#define STRUCT_FUNC_PTRS(S) ((void**)&S)

/**
 * Loads function out of an object file.
 * 
 * @note \c description may be \c NULL
 * @note \c names needs to have a 'NULL' entry at the end
 *
 * @param path Absolute path pointing to the object file
 * @param minVersion Minimum version required - otherwise loading fails
 * @param functionNames Names of the functions that should be loaded 
 *      (NULL-terminated)
 * @param functionPtrs (out) Array of function pointers. Use STRUCT_FUNC_PTRS
 *      in case you you want to pass a struct instead.
 * @param description (out) Target for the plugin description, or \c NULL
 * @return Plugin-handle, or \c NULL in case of an error
 * @see unloadPlugin
 */
extern void* loadPlugin(const char* path, uint16_t minVersion, 
                        const char* functionNames[],
                        void** functionPtrs,
                        const char** description);

/**
 * Releases the resources of a plugin.
 *
 * @param handle Plugin handle
 * @see loadPlugin
 */
extern void unloadPlugin(void* handle);

#endif // !__PLUGIN_H__

