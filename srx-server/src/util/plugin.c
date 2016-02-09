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
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 * 0.1.0.0  - 2010/01/15 - pgleichm
 *            * Code created.
 */
#include <dlfcn.h>
#include "util/plugin.h"
#include "util/log.h"

/**
 * This list contains the names of the function that are required for each
 * plugin
 */
static const char* PredefinedNames[] = {
  "getPluginVersion",
  "getPluginDescription",
  NULL
};

/**
 * Function pointers of all required functions.
 */
typedef struct { 
  GetPluginVersion      getVersion;
  GetPluginDescription  getDesc;
} PredefinedFunctions;

/**
 * Loads a set of functions.
 *
 * @param handle Object file handle
 * @param names Function names
 * @param funcPtrs (out) Target function pointer array
 * @param expected (out) Number of functions (= number of function names)
 * @param found (out) Number of found functions
 */
static void load(void* handle, const char* names[], void** funcPtrs, 
                 int* expected, int* found) {
  int idx;

  *found = 0;
  for (idx = 0; names[idx] != NULL; idx++) {
    funcPtrs[idx] = dlsym(handle, names[idx]);
    if (funcPtrs[idx] != NULL) {
      (*found)++;
    }
  }

  *expected = idx;
}

void* loadPlugin(const char* path, uint16_t minVersion, 
                 const char* functionNames[], void** functionPtrs,
                 const char** description) {
  void*               handle;
  PredefinedFunctions preFuncs;
  int                 num, found;

  // Try to load the file
  handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    RAISE_ERROR("Failed to load the plugin '%s' : %s", path, dlerror());
    return NULL;
  }

  // Resolve the predefined functions
  load(handle, PredefinedNames, STRUCT_FUNC_PTRS(preFuncs), &num, &found);
  if (found != num) {
    RAISE_ERROR("Invalid plugin");
    dlclose(handle);
    return NULL;
  }

  // Minimum version?
  if (preFuncs.getVersion() < minVersion) {
    RAISE_ERROR("Invalid plugin version (%u < %u)",
               preFuncs.getVersion(), minVersion);
    dlclose(handle);
    return NULL;
  }

  // Resolve the user-functions
  load(handle, functionNames, functionPtrs, &num, &found);
  if (found != num) {
    RAISE_ERROR("Plugin did not contain all functions (exp. = %d, found = %d)",
               num, found);
    dlclose(handle);
    return NULL;
  }

  // In case the user requested the description
  if (description != NULL) {
    *description = preFuncs.getDesc();
  }

  return handle;
}

inline void unloadPlugin(void* handle) {
  if (handle != NULL) {
    dlclose(handle);
  }
}

