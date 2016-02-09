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
 * A small unit test suite for C
 *
 * @note Define TRACE_TEST before including this file to print every 
 *       checked condition.
 *
 * @par A typical skeleton
 *
 * @code
 * TEST_BEGIN(ONE, "Example")
 *   int number;
 *   :
 *   FAIL_UNLESS(number == 3, "Invalid value for x");
 * TEST_CLEANUP
 *     :
 * TEST_END
 *
 * TEST_BEGIN(TWO, "Another example")
 *   char* msg;
 *   :
 *   msg = getMessage(...);
 *   INTERNAL_STOP_UNLESS(msg != NULL); // Should never fail
 *   :
 *   IF_COND(!SAFE_STRCMP(msg, "Original")) {
 *     RAISE_ERROR("Message text is incorrect")
 *     :
 *   }
 *
 * TEST_END_NO_CLEANUP
 *
 * int main(int argc, char* argv[]) {
 *   TEST_SUITE_RUN(ONE);
 *   TEST_SUITE_RUN(TWO);
 *   TEST_SUITE_RETURN();
 * }
 * @endcode
 *
 * This will:
 * -# Run the two tests "ONE" and "TWO"
 * -# Print the number of checks that were executed and how many of them failed
 * -# Return the number of failed checks as program exit code
 *
 * @version 0.3.0.10
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.0.10 - 2015/11/09 - oborchert
 *            * Added Changelog
 *            * Fixed speller in documentation header
 * 0.1.0    - 2010/06/02 -pgleichm
 *            * Ability to trace
 *          - 2010/05/15 - pgleichm
 *            * Initial release
 *          - 2010/04/19 -pgleichm
 *            * Code created. 
 * 
 */
// @TODO: Check if it can be deleted
#ifndef __TEST_H__
#define __TEST_H__

#include <string.h>

/**
 * Globally accessible variables
 */
static int  test_local_checks, test_local_err;
static int  test_total_checks = 0;
static int  test_total_err    = 0;

/*-----------------
 * Test body macros
 */

/**
 * Begins a test.
 *
 * @param ID Test identifier (alpha-numeric and underscore)
 * @param DESC Short description of the test
 * @see TEST_END
 * @see TEST_END_NO_CLEANUP
 */
#define TEST_BEGIN(ID, DESC) \
  void test_ ## ID () { \
    test_local_checks = 0; \
    test_local_err = 0; \
    fprintf(stderr, "*** Test %s - %s ***\n", #ID, DESC);

/** 
 * Defines the clean-up block for the current test.
 *
 * @see TEST_END_NO_CLEANUP
 */
#define TEST_CLEANUP \
  end_test:

/**
 * Ends the current test.
 *
 * @note Needs to be preceded by TEST_CLEANUP.
 *
 * @see TEST_BEGIN
 * @see TEST_END_NO_CLEANUP
 */
#define TEST_END \
    fprintf(stderr, "Checks: %d, errors: %d\n\n", \
            test_local_checks, test_local_err); \
    test_total_checks += test_local_checks; \
    test_total_err += test_local_err; \
  }

/**
 * Ends the current test - w/o an explicit clean-up block.
 *
 * @see TEST_BEGIN
 * @see TEST_END
 */
#define TEST_END_NO_CLEANUP \
  end_test: \
  TEST_END


/**
 * Runs a certain test.
 *
 * @param ID Test identifier
 * @see TEST_BEGIN
 */
#define TEST_SUITE_RUN(ID) \
  test_ ## ID()

/**
 * Place this at the end of the \c main function. 
 * This prints the number of checks and errors and returns the number of
 * errors as exitcode.
 */
#define TEST_SUITE_RETURN() \
  fprintf(stderr, "=> Total checks: %d, errors: %d\n", \
          test_total_checks, test_total_err); \
  return (test_total_err > 255) ? -1 : test_total_err

/*-----------------
 * Condition macros
 */

/**
 * Notes an error. 
 * It is recommended to combine this with the IF_COND macro.
 *
 * @param FMT Description of what caused the error (printf format string)
 * @param ... Arguments
 * @see IF_COND
 */
#define FAIL(FMT, ...) \
  { \
    test_local_err++; \
    fprintf(stderr, "FAIL: (%s:%d) " FMT "\n", \
            __FILE__, __LINE__, ## __VA_ARGS__); \
  }

/* Internal use only */
#ifdef TRACE_TEST
  #define TRACE_CONDITION(COND) \
    fprintf(stderr, "%d. " #COND "\n", test_local_checks)
#else
  #define TRACE_CONDITION(COND)
#endif

/**
 * Tests a condition.
 * FAIL needs to be called explicitely.
 * 
 * @param COND Condition
 * @see FAIL
 */
#define IF_COND(COND) \
  test_local_checks++;   \
  TRACE_CONDITION(COND); \
  if (COND)

/**
 * Aborts the current test.
 */
#define STOP_TEST() \
  goto end_test

/**
 * Tests a condition and raises an error in case the outcome is negative.
 *
 * @param COND Condition
 * @param FMT Description of the negative outcome (printf format string)
 * @param ... \c FMT arguments
 * @see FAIL_STOP_UNLESS
 */
#define FAIL_UNLESS(COND, FMT, ...) \
  IF_COND(!(COND)) { \
    FAIL(FMT " (" #COND ")", ## __VA_ARGS__) \
  }

/**
 * Tests a condition, raises an error in case the outcome is negative and
 * stops further evaluation of the current test.
 *
 * @param COND Condition
 * @param FMT Description of the negative outcome (printf format string)
 * @param ... \c FMT arguments
 * @see FAIL_UNLESS
 */
#define FAIL_STOP_UNLESS(COND, FMT, ...) \
  IF_COND(!(COND)) { \
    FAIL(FMT " (" #COND ") [stopping]", ## __VA_ARGS__); \
    STOP_TEST(); \
  }

/*----------------
 * Internal macros
 */

/**
 * A test cannot continue b/c of an internal error.
 *
 * @param COND Condition
 */
#define INTERNAL_STOP_UNLESS(COND) \
  if (!(COND)) { \
    fprintf(stderr, "INTERNAL: (%s:%d) " #COND " [stopping]\n", \
            __FILE__, __LINE__); \
    goto end_test; \
  }

/*--------------
 * Helper macros
 */

/**
 * Returns a textual representation of the boolean value.
 *
 * @param VAL Boolean value
 */
#define BOOL_STR(VAL)  ((VAL) ? "true" : "false")

/**
 * Only executes a command if the given variable is not \c NULL.
 *
 * @param VAR Variable
 * @param CMD Command
 */
#define DO_UNLESS_NULL(VAR, CMD) \
  if ((VAR) != NULL) { \
    CMD; \
  }

/** 
 * Free's a variable only if it is not \c NULL.
 *
 * @param VAR Variable
 */
#define SAFE_FREE(VAR) \
  DO_UNLESS_NULL(VAR, free(VAR))

/**
 * Compares two strings safely.
 * Two \c NULL values are considered equal.
 *
 * @param A String A
 * @param B String B
 * @return \c true = equal, \c false = not equal
 */
#define SAFE_STRCMP(A, B) \
  ((A == NULL) ? ((B == NULL) ? true : false) : !strcmp(A, B))

#endif // !__TEST_H__

