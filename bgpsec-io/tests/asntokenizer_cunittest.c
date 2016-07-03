/*
 * File:   asntokenizer_cunittest.c
 * Author: borchert
 *
 * Created on Aug 5, 2015, 10:25:30 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/Basic.h>
#include "../ASNTokenizer.h"
/*
 * CUnit Test Suite
 */
u_int32_t asn;

int init_suite(void) {
  asntok(" 10 1.20 ");
  return 0;
}

int clean_suite(void) 
{
  asntok_clear();
  return 0;
}

void test1() {
  CU_ASSERT(asntok_next(&asn) == true);
}

void test2() {
  CU_ASSERT(asn == 10);
}

void test3() {
  CU_ASSERT(asntok_next(&asn) == true);
}

void test4() {
  u_int32_t result = (1 << 16) + 20;
  CU_ASSERT(asn == result);
}

void test5() {
  CU_ASSERT(asntok_next(&asn) == false);
}

void test6() {
  asn = 100;
  asntok_next(&asn); // tokenizer at the end.
  CU_ASSERT(asn == 100);
}

void test7() {
  asntok_reset();
  CU_ASSERT(asntok_next(&asn) == true);
}

void test8() {
  CU_ASSERT(asn == 10);
}

void test9() {
  asntok_clear();
  CU_ASSERT(asntok_next(&asn) == false);
}

void test10() {
  CU_ASSERT(asn == 10);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("asntokenizer_cunittest", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (    (NULL == CU_add_test(pSuite, "test1",  test1)) 
       || (NULL == CU_add_test(pSuite, "test2",  test2))
       || (NULL == CU_add_test(pSuite, "test3",  test3))
       || (NULL == CU_add_test(pSuite, "test4",  test4))
       || (NULL == CU_add_test(pSuite, "test5",  test5))
       || (NULL == CU_add_test(pSuite, "test6",  test6))
       || (NULL == CU_add_test(pSuite, "test7",  test7))
       || (NULL == CU_add_test(pSuite, "test8",  test8))
       || (NULL == CU_add_test(pSuite, "test9",  test9))
       || (NULL == CU_add_test(pSuite, "test10", test10))
     ) 
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();
}
