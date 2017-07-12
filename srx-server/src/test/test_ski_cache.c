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
 *  
 * This files is used for testing the SKI Cache functions.
 *
 * @version 0.5.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/06/30 - oborchert
 *            * Added tests 7 and 8
 *          - 2017/06/29 - oborchert
 *            * Restructured tests
 *          - 2017/06/20 - oborchert
 *            * File created
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <srx/srxcryptoapi.h>
#include "client/srx_api.h"
#include "server/ski_cache.h"
#include "server/rpki_queue.h"
#include "util/bgpsec_util.h"
#include "util/log.h"

typedef struct {
  u_int8_t      ski[SKI_LENGTH];
  u_int32_t     asn;
  u_int8_t      algoID;
  int           noUpdates;
  SRxUpdateID*  updateID;
} TEST_SKI_DATA;

/** The RPKI Queue */
RPKI_QUEUE* rpki_queue = NULL;

/** The Test Data */
TEST_SKI_DATA** testData;
/** The number of elements to be generated*/
u_int8_t noElements = 0;

/** Specifies the verbose setting. */
bool verbose = false;
bool verbose_init = false;

/** This is needed in case a failed assert does NOT exit and printPassed is 
 * called! */
bool assertFailed = false;

/** The SKI cache */
SKI_CACHE* cache = NULL;

/** Number of test data elements. */
//#define NO_ELEMENTS 8
#define MAX_NO_ELEMENTS 8

/** Max number of updates per data element. */
#define MAX_NO_UPDATE_IDS  5
#define NO_UPDATE_IDS      0

// The last two are additional SKI's that will be added within a test.
// The SKI's MUST be unique.
//
// The first 2 SKI's must be assigned as follows:
// Updates: ASN=64495, ALGO=1, SKI=AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154
//          ASN=65536, ALGO=1, SKI=47F23BF1AB2F8A9D26864EBBD8DF2711C74406EC
//
char* arrSKI[MAX_NO_ELEMENTS] = {
  "AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154\0",
  "47F23BF1AB2F8A9D26864EBBD8DF2711C74406EC\0",
  "3A7C104909B37C7177DF8F29C800C7C8E2B8101E\0",
  "8E232FCCAB9905C3D4802E27CC0576E6BFFDED64\0",
  "8BE8CA6579F8274AF28B7C8CF91AB8943AA8A260\0",
  "FB5AA52E519D8F49A3FB9D85D495226A3014F627\0",
  "FDFEE7854889F25BF6ECB88AFAF39CE0EBC41E08\0",
//  "7BEE8A35FD78325932ADEF853A6B1F340C1F3DEF\0",
//  "C38D869FF91E6307F1E0ABA99F3DA7D35A106E7F\0",
  "18494DAA1B2DFD80636AE943D9DC9FF42C1AF9D9\0"  
};

// This update was generated using the first 2 SKI's above
// This 2 updates are taken from rfc8208
// Updates: ASN=64495, ALGO=1, SKI=AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154
//          ASN=65536, ALGO=1, SKI=47F23BF1AB2F8A9D26864EBBD8DF2711C74406EC
//
char* bgp_update_hex[2] = {
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
        "010302000000EC400101028004040000" \
        "0000800E0D00010104C63364640018C0" \
        "0002901E00CD000E0100000100000100" \
        "0000FBF000BF0147F23BF1AB2F8A9D26" \
        "864EBBD8DF2711C74406EC0048304602" \
        "2100EFD48B2AACB6A8FD1140DD9CD45E" \
        "81D69D2C877B56AAF991C34D0EA84EAF" \
        "371602210090F2C129ABB2F39B6A0796" \
        "3BD555A87AB2B7333B7B91F1668FD861" \
        "8C83FAC3F1AB4D910F55CAE71A215EF3" \
        "CAFE3ACC45B5EEC15400483046022100" \
        "EFD48B2AACB6A8FD1140DD9CD45E81D6" \
        "9D2C877B56AAF991C34D0EA84EAF3716" \
        "0221008E21F60E44C6066C8B8A95A3C0" \
        "9D3AD4379585A2D728EEAD07A17ED7AA" \
        "055ECA\0",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
        "011002000000F9400101028004040000" \
        "0000800E1A0002011020010010000000" \
        "0000000000C6336464002020010DB890" \
        "1E00CD000E01000001000001000000FB" \
        "F000BF0147F23BF1AB2F8A9D26864EBB" \
        "D8DF2711C74406EC00483046022100EF" \
        "D48B2AACB6A8FD1140DD9CD45E81D69D" \
        "2C877B56AAF991C34D0EA84EAF371602" \
        "2100D1B94F6251046D2136A105B0F472" \
        "7CC5BCD674D97D28E61B8F43BDDE91C3" \
        "0626AB4D910F55CAE71A215EF3CAFE3A" \
        "CC45B5EEC15400483046022100EFD48B" \
        "2AACB6A8FD1140DD9CD45E81D69D2C87" \
        "7B56AAF991C34D0EA84EAF3716022100" \
        "E2A02C68FE53CB96934C781F5A14A297" \
        "1979200C9156EDF855058E8053F4ACD3\0" };

/** The array of BGPsec_PATH attributes, also filled in the main method. */
SCA_BGP_PathAttribute* bgp_BGPsec_PATH[2] = {NULL, NULL};


// Due to the testing using the index to max parts togener, the first 2 ASNs
// MUST be 64496, and 65536
// A: append, Ih: insert header, Im: Insert middle/in between, -: do nothing
//                                      A      A:U1   Ih -  -  A  A  A:U2         
u_int32_t arrASN[MAX_NO_ELEMENTS]    = {64496, 65536, 1, 1, 1, 1, 3, 0x00020000};
//                                      A          -  -  A  Im -  -  -
u_int8_t  arrAlgoID[MAX_NO_ELEMENTS] = {1,         1, 1, 3, 2, 1, 1, 1};
// zero value means no update
SRxUpdateID arrUpdateID[MAX_NO_ELEMENTS][MAX_NO_UPDATE_IDS] = {
   {0xab11, 0xab10, 0xab01, 0, 0},
   {0xab21, 0xab20, 0xab01, 0, 0},
   {0xab31, 0xab30, 0xab02, 0, 0},
   {0xab41, 0xab40, 0xab02, 0, 0},
   {0xab51, 0xab50, 0xab03, 0, 0},
   {0xab61, 0xab60, 0xab03, 0, 0},
   {0xab71, 0xab70, 0xab04, 0, 0},
   {0xab81, 0xab80, 0xab04, 0, 0},
};

#define V_FUNC_SIZE 1
// For X use the test suite for y use the test
char* vFunc[V_FUNC_SIZE] = {"test_Xy\0"};

/** Indicates that the program exits on assert failures */
bool exitOnAssertFailure = true;


static void freeTestData();

////////////////////////////////////////////////////////////////////////////////
// Test evaluation and print functions
////////////////////////////////////////////////////////////////////////////////

/**
 * Check if the given function should have verbose mode on.
 * @param func Function name
 * @return true - enable verbose; false - leave as is.
 */
static bool checkVerbose(const char* func)
{
  // initialize with global verbose setting
  bool verboseFunc = verbose;
  int idx = 0;
  for (; !verboseFunc & idx < V_FUNC_SIZE; idx++)
  {
    verboseFunc = verboseFunc || (strcmp(func, vFunc[idx]) == 0);
  }  
  
  return verboseFunc;
}

/**
 * Print the content of the data object on the screen
 * 
 * @param data The data object to be printed
 */
static void printDataElement(TEST_SKI_DATA* data, char* prefix)
{
  int idx;
  u_int8_t* bNum = (u_int8_t*)data->ski;
  if (prefix == NULL)
  {
    prefix = "\0";
  }
  printf ("%sData: {ASN=%u; SKI='", prefix, data->asn);
  for (idx = 0; idx < SKI_LENGTH; idx++)
  {
    printf ("%02X", *bNum);
    bNum++;
  }
  printf("'; ALGOID=%u", data->algoID);
  for (idx = 0; idx < data->noUpdates; idx++)
  {
    printf("; UID=%u", data->updateID[idx]);
  }
  if (idx == 0)
  {
    printf("; UID=N/A}\n");    
  }
}
////////////////////////////////////////////////////////////////////////////////
// ASSERT METHOD(S)
////////////////////////////////////////////////////////////////////////////////

/**
 * check the value against expected, if not match then exit.
 * 
 * @param val the value to be checked
 * @param expected the value to be checked against (expected value)
 * @param error the error string in case of exit
 */
static void assert_int(int val, int expected, char* error)
{
  if (val != expected)
  {
    if (error == NULL)
    {
      error = "";
    }
    printf ("Error: %s; Expected %i but received %i\n", error, expected, val);
    
    ski_releaseCache(cache);
    rq_releaseQueue(rpki_queue);
    
    freeTestData();      
    
    printf ("          Failed!\n");
    if (exitOnAssertFailure)
    {
      printf ("Abort further testing!");      
      exit (EXIT_FAILURE);
    }
    else
    {
      printf ("INFO: Exit is disabled!");
      assertFailed = true;
    }
  }
}

/**
 * check the value against expected, if not match then exit.
 * 
 * @param val the value to be checked
 * @param expected the value to be checked against (expected value)
 * @param error the error string in case of exit
 */
static void assert_info (SKI_CACHE_INFO* info_1, SKI_CACHE_INFO* info_2, 
                         char* error)
{
  char* myError = error;
  assert_int(info_1->count_AS2,     info_2->count_AS2,     myError);
  assert_int(info_1->count_cAlgoID, info_2->count_cAlgoID, myError);
  assert_int(info_1->count_cData,   info_2->count_cData,   myError);
  assert_int(info_1->count_cNode,   info_2->count_cNode,   myError);
  assert_int(info_1->count_cUID,    info_2->count_cUID,    myError);
  assert_int(info_1->count_keys,    info_2->count_keys,    myError);
  assert_int(info_1->count_updates, info_2->count_updates, myError);
}

////////////////////////////////////////////////////////////////////////////////
// Test preparation functions
////////////////////////////////////////////////////////////////////////////////

/**
 * Create the data object <SKI, AND, ALGO_ID [, UpdateID]*>
 * 
 * @param asn The AS number.
 * @param skiStr The SKI hex string, will be converted into a byte array.
 * @param algoID The algorithm id
 * @param noUpdates number of updates (0..255)
 * @param updateIDs The array of update IDs (NULL if noUpdates = 0)
 */
static TEST_SKI_DATA* createData(u_int32_t asn, char* skiStr, u_int8_t algoID, 
                  u_int8_t noUpdates, SRxUpdateID* updateIDs)
{  
  TEST_SKI_DATA* tdElem = malloc(sizeof(TEST_SKI_DATA));
  memset(tdElem, 0, sizeof(TEST_SKI_DATA));
  
  int idx, strIdx;
  int strLen = strlen(skiStr);
  char byteStr[] = { '0', 'x', '0', '0', '\0' };
  
  for (idx = 0, strIdx = 0; idx < SKI_LENGTH, strIdx < strLen; idx++, strIdx++)
  {
    byteStr[2] = skiStr[strIdx++];
    byteStr[3] = skiStr[strIdx];
    sscanf (byteStr, "%x", &tdElem->ski[idx]);
  }
  
  tdElem->asn       = asn;
  tdElem->algoID    = algoID;
  tdElem->noUpdates = noUpdates;
  tdElem->updateID  = updateIDs;
  
  return tdElem;
}

/**
 * Release the allocated memory used for data
 * 
 * @param tdElem The test data object 
 */
static void freeDataElement(TEST_SKI_DATA* tdElem)
{
  tdElem->updateID = NULL;
  memset (tdElem, 0, sizeof(TEST_SKI_DATA));
  free (tdElem);
}

/**
 * Free the test data array.
 */
static void freeTestData()
{
  if (testData != NULL)
  {
    int idx = 0;
    for (; idx < noElements; idx++)
    {
      freeDataElement(testData[idx]);
      testData[idx]=NULL;
    }
    free(testData);
    testData = NULL;
  }
  
  free(bgp_BGPsec_PATH[0]);
  free(bgp_BGPsec_PATH[1]);
}

/**
 * Generate the test data structure
 * 
 * @param useUpdates if true, update-id's are added to the updates.
 * 
 * @return The test data array
 */
static void createTestData(bool useUpdates)
{
  // First clean up the test data
  freeTestData();
  int idx = 0;
  int idx2 = 0;
  int size = sizeof(TEST_SKI_DATA*) * noElements;
  testData = malloc(size);  
  memset(testData, 0, size); 
  
  int           numUpdates = 0;
  SRxUpdateID*  updates    = NULL;
  for (; idx < noElements; idx++)
  {
    updates    = NULL;
    numUpdates = 0;
    if (useUpdates)
    {
      updates = (SRxUpdateID*)arrUpdateID[idx];
      for (; numUpdates < NO_UPDATE_IDS; numUpdates++)
      {
        if (*updates != 0)
        {
          updates++; 
          continue;
        }
        break;
      }
    }
    testData[idx] = createData(arrASN[idx], arrSKI[idx], arrAlgoID[idx], 
                               numUpdates, updates);
  }
  
  int lenU[2];
  // Create the updates and get the BGPsec_PATH attribute from each.
  bgp_BGPsec_PATH[0] = (SCA_BGP_PathAttribute*)util_getBGPsec_PATH(
                                                   bgp_update_hex[0], &lenU[0]);
  bgp_BGPsec_PATH[1] = (SCA_BGP_PathAttribute*)util_getBGPsec_PATH(
                                                   bgp_update_hex[1], &lenU[1]);  
  
  if (verbose)
  {
    printf ("Created Test Data:\n");
    for (idx = 0; idx < noElements; idx++)
    {
      printDataElement(testData[idx], " -> ");
    }
    
    for (idx = 0; idx < 2; idx ++)
    {
      printf ("Update %i:\n", idx);
      char* cPtr = bgp_update_hex[idx];
      while (strlen(cPtr) >= 32)
      {
        printf ("  %1.16s ", cPtr);
        cPtr += 16;
        printf (" %1.16s\n", cPtr);
        cPtr += 16;
      }
      if (strlen(cPtr) != 0)
      {
        if (strlen(cPtr) > 16)
        {
          printf ("  %1.16s", cPtr);
          cPtr += 16;          
          printf (" %s\n", cPtr);
        }
        else
        {
          printf ("  %s\n", cPtr);
        }
      }      
      printf ("BGPsec_PATH %i:\n  ", idx);
      u_int8_t* bgpsecPath = (u_int8_t*)bgp_BGPsec_PATH[idx];
      for (idx2 = 0; idx2 < lenU[idx]; idx2++, bgpsecPath++)
      {
        if (idx2 != 0)
        {
          if (idx2 % 16 == 0)
          {
            printf ("\n  ");
          }
          else if (idx2 % 8 == 0)
          {
            printf ("  ");
          }
        }
        printf ("%02X", *bgpsecPath);
      }
      printf ("\n");
    }
  }  
}

/**
 * Clean the SKI cache and the RPKI Cache
 * @param test
 */
static void cleanTest(int test)
{
  // Now clean up 
  rq_empty(rpki_queue);
  assert_int(rq_size(rpki_queue), 0, "Could not empty RPKI Queue");

  ski_clean(cache, SKI_CLEAN_ALL);
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  int sum =   info.count_AS2 + info.count_cAlgoID + info.count_cData 
            + info.count_cNode + info.count_cUID;
  char str[255];
  snprintf(str,255, "After Test Suite #%i: SKI Cache not completely emptied", 
           test);
  assert_int(sum, 0, str);
  
}

/**
 * Do print the Passed message only if no assert since the last call failed.
 * Thi call resets the value of 'assertFailed'
 */
void printPassed()
{
  if (!assertFailed)
  {
    printf ("          Passed!\n");  
  }
  // Now reset assertFailed
  assertFailed = false;
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 1
////////////////////////////////////////////////////////////////////////////////
static void test_1a(char* name, int noKeys, bool printPassed);
static void test_1b();

/** run test suite 1 - Test SKI key registration */
static void test_1()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);
  
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 1!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 1: Test the registration and removal of keys using empty\n"
          "        cache\n");
  test_1a("1a", noElements, true);              
  //Test #1b unregister key data - Cache expected to be empty afterwards
  test_1b();    
  // Expect RPI QUEUE to be empty
  assert_int(rq_size(rpki_queue), 0, "Expect RPKI QUEUE to be empty!");
  cleanTest(1);  
  verbose = oldVerbose;
}

/** 
 * Register the given data as key data - verifies that the RPKI QUEUE is empty.
 * does NOT clean the ski cache.
 * 
 * @param name The test name (1a, 3a, or 4a). If NULL no header is presented.
 * @param noKeys Allows to specify the number of keys to be installed.
 * @param printIfPassed if false suppress the passed notice.
 */
static void test_1a(char* name, int noKeys, bool printIfPassed)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);
  
  // Used for 1a, 3a, and 4a
  if (name != NULL)
  {
   printf ("Test #%s: Register %i Key Data elements:\n", name, noElements);
  }
  
  int idx = 0;
  TEST_SKI_DATA* data = NULL;  
  SKI_CACHE_INFO info;
  
  for (; idx < noKeys; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Register key SKI");
    }
    ski_registerKey(cache, data->asn, data->ski, data->algoID);
  }
  // Check that all keys are installed.
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_keys, noKeys, "Not all keys are registered!");  
  // Here Nothing is 
  assert_int(rq_size(rpki_queue), 0, "RPKI Queue must be empty!");
  verbose = oldVerbose;
  
  if (printIfPassed)
  {
    // Here itr might be supressed because this test might be called from 
    // within another test than 1a
    printPassed();
  }
}

/** 
 * Unregister the given data as key data
 */
static void test_1b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #1b: Unregister all %i Key Data elements:\n", noElements);
  int idx = 0;
  TEST_SKI_DATA* data;
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }  
  // Here Nothing is 
  assert_int(rq_size(rpki_queue), 0, "RPKI Queue must be empty!");
  SKI_CACHE_INFO cInfo;
  // Examine the ski cache.
  ski_examineCache(cache, &cInfo, verbose);
  int elemCount = cInfo.count_cData+cInfo.count_cUID;
  if (elemCount > 0)
  {
    ski_examineCache(cache, &cInfo, true);    
  }
  assert_int(elemCount, 0, "SKI Cache still contains Data or Update Nodes");
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 2
////////////////////////////////////////////////////////////////////////////////
static void test_2a();
static void test_2b();

/** run test suite 2 - Test Update registration */
static void test_2()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 2!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 2: Test the registration and removal of BGPsec UPDATES\n"
          "        using empty cache\n");
  // Now register two updates.
  test_2a();
  // Now unregister the same two updates.
  test_2b();
  // Expect RPI QUEUE to be empty
  assert_int(rq_size(rpki_queue), 0, "Expect RPKI QUEUE to be empty!");
  cleanTest(2);
  verbose = oldVerbose;
}

/**
 * This test will register 2 updates, each update has two hops, each hop
 * uses its own SKI. Both updates use the same path -> 2 ski's stored,
 * each one has two update ids.
 * 
 * The RPKI_QUEUE should be empty here
 */
static void test_2a()
{     
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #2a: Register 2 BGPsec update:\n");
  // Now store the updates
  SKI_CACHE_INFO info;
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData , 2, "Expected to have two SKIs stored!");
  assert_int(info.count_cUID  , 2, "Expected to have two Update IDs stored!");
  ski_registerUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData , 2, "Expected to have two SKIs stored!");
  assert_int(info.count_cUID  , 4, "Expected to have four Update IDs stored!");

  // Now check RPKI Cache
  assert_int(rq_size(rpki_queue), 0, "RPKI Queue should be empty!");  
  verbose = oldVerbose;
  printPassed();
}

/**
 * This test will unregister the two previously registered updates.
 * 
 * the RPKI cache should be empty at this point
 */
static void test_2b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #2b: Unregister both BGPsec update:\n");
  // Now remove the updates
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  ski_unregisterUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData, 2, 
                             "Did not expect the complete data being removed!");
  assert_int(info.count_cUID , 2, "Only expected update registrations removed!");
  ski_unregisterUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  ski_examineCache(cache, &info, verbose);  
  assert_int(info.count_cUID+info.count_cData, 0, 
                              "Expected to both update registrations removed!");

  // Now check RPKI Cache
  assert_int(rq_size(rpki_queue), 0, "RPKI Queue should be empty!");
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 3
////////////////////////////////////////////////////////////////////////////////
static void test_3a();
static void test_3b();


/** run test suite 3 - Test Update registration */
static void test_3()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 3!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 3: Using one key and one update that requires the key,\n"
          "        this test tests the notification mechanism using the\n"
          "        RPKI Queue\n");

  // Install the update
  test_3a();
  // Install the key
  test_3b(); 
  
  cleanTest(3);
  verbose = oldVerbose;  
}

/**
 * Install the 1st update 
 */
static void test_3a()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #3a: Resister one update (2 hops).\n");
  SKI_CACHE_INFO info;
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected to have the Update ID's stored twice"
             ", once for each of the two update-SKIs!");  
  assert_int(rq_size(rpki_queue), 0, "RPKI QUEUE should be empty.");
  
  verbose = oldVerbose;  
  printPassed();
}

/**
 * Install the 1st key
 */
static void test_3b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);
  
  printf ("Test #3b: Register one key.\n");
  
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cNode, 2, "Expect to have 2 CACHE NODES provided by 3a");
  assert_int(rq_size(rpki_queue), 0, "RPKI QUEUE should be empty.");

  // Use the test_1a function to load the first key.
  TEST_SKI_DATA* data = testData[0];
  if (verbose)
  {
    printDataElement(data, " Register key SKI");
  }
  ski_registerKey(cache, data->asn, data->ski, data->algoID);
  
  assert_int(rq_size(rpki_queue), 1, "RPKI QUEUE should contain 1 element.");
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cNode, 2, "Expect to have 2 CACHE NODES provided by 3a");
  assert_int(info.count_keys, 1, "Expect to have 1 Key registered");

  verbose = oldVerbose;  
  printPassed();
}



////////////////////////////////////////////////////////////////////////////////
// Test Suite 4
////////////////////////////////////////////////////////////////////////////////

static void test_4a();
static void test_4b();
static void test_4c();
static void test_4d();
static void test_4e();
static void test_4f();

/** run test suite 4 - Test Update registration */
static void test_4()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 4!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 4: Using 2 updates and 8 keys, this test simulates adding\n"
          "        and removing of keys with different filling states of\n"
          "        the ski cache.\n");

  test_4a(); // Register all SKI Keys  
  test_4b(); // Register one update  
  test_4c(); // Remove all SKI keys  
  test_4d(); // Register other update.
  test_4e(); // Register all SKI Keys  
  test_4f(); // Remove all SKI keys.
  // RPKI QUEUE still should have two events.
  
  RPKI_QUEUE_ELEM rElem;
  int noQueueElems = 0;
  while (rq_dequeue(rpki_queue, &rElem))
  {
    noQueueElems++;
  }
  assert_int(noQueueElems, 2, "Expected 2 elements in the RPKI QUEUE");
  
  cleanTest(4);  
  verbose = oldVerbose;
}

/**
 * Test 4a does effectively the same as Test 1a
 */
static void test_4a()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  // Same as 1a
  test_1a("4a", noElements, true);  
  verbose = oldVerbose;
}

/**
 * Test 4b Adds one Update (2 hops) to the already registered key data
 */
static void test_4b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #4b: Resister one update (2 hops).\n");
  SKI_CACHE_INFO info;
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected to have two Update ID's stored!");  
  assert_int(rq_size(rpki_queue), 0, "RPKI QUEUE should be empty.");
  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Test 4b Remove all key registrations. It is expected that 2 SKI's remain,
 * each one representing one of the SKI for the registered update.
 * Also it is expected to see one queues RPKI event
 */
static void test_4c()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #4c: Remove all key registrations.\n");
  int idx = 0;
  SKI_CACHE_INFO info;
  TEST_SKI_DATA* data;
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }  
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_keys,  0, "All keys are expected to be removed.");
  assert_int(info.count_cData, 2, "Only 2 data nodes should remain, one for "
                                  "each hop of the registered update.");
  assert_int(info.count_cUID,  2, "Only 2 update ID's should remain, one for "
                                  "each of the remaining data nodes.");
  assert_int(rq_size(rpki_queue), 1, "RPKI QUEUE should have one event.");
  verbose = oldVerbose;
  printPassed();
}

/**
 * Leaving the RPKI event alone, We add the second update to the list.
 */
static void test_4d()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #4d: Register the other update.\n");
  
  SKI_CACHE_INFO info;
  ski_registerUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData, 2, "Expected to have 2 data objects stored - "
                                  "both updates use same SKIs!");    
  assert_int(info.count_cUID,  4, "Expected to have four Update ID's stored!");      
  assert_int(rq_size(rpki_queue), 1, "RPKI QUEUE still only should have one"
                                     " event.");
  verbose = oldVerbose;
  printPassed();
}

static void test_4e()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #4e: Register all SKI Keys\n");
  
  int idx = 0;
  TEST_SKI_DATA* data = NULL;  
  SKI_CACHE_INFO info;
  
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Register ");
    }
    ski_registerKey(cache, data->asn, data->ski, data->algoID);
  }
  // Check that all keys are installed.
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData, noElements, "Not all keys are installed!");  
  assert_int(rq_size(rpki_queue), 2, "RPKI QUEUE should have two events.");
  verbose = oldVerbose;
  printPassed();
}

/**
 * Unregister all SKI keys.
 */
static void test_4f()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #4f: Unregister all SKI Keys\n");
  
  int idx = 0;
  SKI_CACHE_INFO info;
  TEST_SKI_DATA* data;
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }  
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cData, 2, "Only 2 data nodes should remain, one for "
                                  "each hop of the 2 registered updates.");
  assert_int(info.count_cUID, 4, "4 update ID's should remain, two for "
                                 "each of the remaining data nodes.");
  assert_int(rq_size(rpki_queue), 2, "RPKI QUEUE still should have two events.");
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 5
////////////////////////////////////////////////////////////////////////////////

static void test_5a();
static void test_5b();

/** run test suite 5 */
static void test_5()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 5!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 5: Test removing updates and keys that are not previously\n"
          "        stored on empty cache.\n");

  test_5a(); // Removal of all keys without prior registration
  test_5b(); // Removal of all updates without prior registration
  
  cleanTest(5);  
  verbose = oldVerbose;
}

/**
 * 
 */
static void test_5a()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #5a: Removal of all keys without prior registration\n");
  
  int idx = 0;
  TEST_SKI_DATA* data;
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }  
  // Here Nothing is 
  assert_int(rq_size(rpki_queue), 0, "RPKI Queue must be empty!");
  
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cNode, 0, "The SKI Cache must be empty!");
  
  verbose = oldVerbose;
  printPassed();
}

/**
 * 
 */
static void test_5b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #5b: Removal of all updates without prior registration\n");
  
  ski_unregisterUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_unregisterUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
    
  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cNode, 0, "The SKI Cache must be empty!");
  
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 6
////////////////////////////////////////////////////////////////////////////////

static void test_6a();
static void test_6b();
static void test_6c();

/** run test suite 6 */
static void test_6()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 6!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 6: Test removing updates and keys that are not previously\n"
          "        stored into a cache previously filled with other data.\n");

  test_6a(); // Removal of all keys without prior registration
  test_6b(); // Removal of all updates without prior registration
  test_6c(); // Removal of one previously not registered update
  
  cleanTest(6);  
  verbose = oldVerbose;
}

/**
 * 
 */
static void test_6a()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #6a: Prepare the SKI cache with 4 keys and the first\n"
          "          update.\n");
  
  SKI_CACHE_INFO info;
  // Register the keys,
  test_1a(NULL, 4, false);  
  // Register the Update
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_keys, 4, "Expected to have all 4 keys stored!");  
  assert_int(info.count_cUID, 2, "Expected to have the Update ID's stored twice"
             ", once for each of the two update-SKIs!");    
  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Unregister non-registered keys on filled cache.
 */
static void test_6b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #6b: Unregister non-registered keys on filled cache.\n");
  
  SKI_CACHE_INFO info_pre, info_post;
  ski_examineCache(cache, &info_pre, verbose);  
  int idx = 0;
  TEST_SKI_DATA* data;
  
  for (idx = 5; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }  
  
  // Examine the cache
  ski_examineCache(cache, &info_post, verbose);
  assert_int(info_post.count_AS2, info_pre.count_AS2,
             "Cache (AS2) changed.");
  assert_int(info_post.count_cAlgoID, info_pre.count_cAlgoID,
             "Cache (cAlgoID) changed.");
  assert_int(info_post.count_cData, info_pre.count_cData,
             "Cache (cData) changed.");
  assert_int(info_post.count_cNode, info_pre.count_cNode,
             "Cache (cNode) changed.");
  assert_int(info_post.count_cUID, info_pre.count_cUID,
             "Cache (cUID) changed.");
  assert_int(info_post.count_keys, info_pre.count_keys,
             "Cache (keys) changed.");
  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Unregister non-registered keys on filled cache.
 */
static void test_6c()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #6c: Unregister non-registered keys on filled cache.\n");
  
  SKI_CACHE_INFO info_pre, info_post;
  ski_examineCache(cache, &info_pre, verbose);  

  ski_unregisterUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  
  // Examine the cache
  ski_examineCache(cache, &info_post, verbose);
  assert_int(info_post.count_AS2, info_pre.count_AS2,
             "Cache (AS2) changed.");
  assert_int(info_post.count_cAlgoID, info_pre.count_cAlgoID,
             "Cache (cAlgoID) changed.");
  assert_int(info_post.count_cData, info_pre.count_cData,
             "Cache (cData) changed.");
  assert_int(info_post.count_cNode, info_pre.count_cNode,
             "Cache (cNode) changed.");
  assert_int(info_post.count_cUID, info_pre.count_cUID,
             "Cache (cUID) changed.");
  assert_int(info_post.count_keys, info_pre.count_keys,
             "Cache (keys) changed.");
  
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 7
////////////////////////////////////////////////////////////////////////////////

static void test_7a();
static void test_7b();

/** run test suite 7 */
static void test_7()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode 
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 7!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 7: Test the registration of an update multiple times\n"
          "        followed by unregistering multiple times.\n");

  test_7a(); // Adding of update one twice and update two ones
  test_7b(); // Removing of update one twice and update two ones
  
  cleanTest(7);  
  verbose = oldVerbose;
}

/**
 * Adding of update one twice and update two ones
 */
static void test_7a()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #7a: Adding of update one twice and update two once.\n");
  
  SKI_CACHE_INFO info;
  // Register the Update
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected the update id to be registered "
          "twice, once with each SKI!");  
  assert_int(info.count_updates, 2, "Expected the update itself to be "
          "registered twice, once with each SKI!");  
  
  // Register the Update again
  ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected the update id to be registered "
          "twice, once with each SKI!");  
  assert_int(info.count_updates, 4, "Expected the update itself to be "
          "registered four times, once with each SKI!");  

  // Register another Update (same route)
  ski_registerUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 4, "Two updates, each with hops = 4 update ID "
          "registrations!");  
  assert_int(info.count_updates, 6, "Expected the all update registrations to "
          "sum up to 6 registrations!");  

  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Removing of update one twice and update two ones
 */
static void test_7b()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  printf ("Test #7b: Removing of update one twice and update two once.\n");
  
  SKI_CACHE_INFO info;
  // Un-register the single Update
  ski_unregisterUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected the update id cUID listed twice!");  
  assert_int(info.count_updates, 4, "Expected the remaining update itself to "
          "be registered four times, twice with each SKI!");  
  
  // Register the Update again
  ski_unregisterUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 2, "Expected the remaining update id to be "
          "registered twice, once with each SKI!");  
  assert_int(info.count_updates, 2, "Expected the remaining update itself to be"
          " registered twice, once with each SKI!");  

  // Register another Update (same route)
  ski_unregisterUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_int(info.count_cUID, 0, "Expect no remaining update id "
                                 "registrations!");  
  assert_int(info.count_updates, 0, "Expect no remaining update "
                                    "registrations!");  

  
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// Test Suite 8
////////////////////////////////////////////////////////////////////////////////

static void test_8a(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo);
static void test_8b(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo);
static void test_8c(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo);
static void test_8d(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo);
static void test_8e(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo);

/** run test suite 8 */
static void test_8()
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose_init);
  int data = info.count_cAlgoID + info.count_cData + info.count_cNode
             + info.count_cUID + rq_size(rpki_queue);
  assert_int(data, 0, "Framework not cleaned for test 8!");
  
  printf ("--------------------------------------------------------------\n");
  printf ("Test 8: Test the cleaning function of the SKI cache.\n");

  SKI_CACHE_INFO keyInfo;
  SKI_CACHE_INFO updInfo;
  
  test_8a(&keyInfo, &updInfo); // Testing SKI_CLEAN_ALL
  test_8b(&keyInfo, &updInfo); // Testing SKI_CLEAN_KEYS
  test_8c(&keyInfo, &updInfo); // Testing SKI_CLEAN_UPDATES
  assert_int(rq_size(rpki_queue), 0, "At this point the RPKI QUEUE still should"
                                     " be empty.");
  test_8d(&keyInfo, &updInfo); // Testing SKI_CLEAN_NONE
                               // - Garbage collection - Keys
  // the queue might have some notifications  from the garbage collection tests 
  // due to calling unregister.
  rq_empty(rpki_queue);
  
  test_8e(&keyInfo, &updInfo); // Testing SKI_CLEAN_NONE
                               // - Garbage collection - Updates
  
  cleanTest(8);  
  verbose = oldVerbose;
}

/**
 * Initialized the cache for test 8
 * it generates noElements (8) KEY registrations and 3 update registrations
 * The updates are once number 0 and twice number 1. Each update has its
 * own update ID.
 * All updates have the same SKI's and AS path
 * 
 * @param name The name of the test (8a, 8b, ...)
 * @param description The description if the test.
 * @param keys if true keys will be registered.
 * @param updates if true, updates will be registered
 */
static void test_8init(char* name, char* description, bool keys, bool updates)
{
  if ((name != NULL) && (description != NULL))
  {
    printf ("Test #%s: %s\n", name, description);
  }
  
  // Initialize all data
  if (keys)
  {
    test_1a (NULL, noElements, false);
  }
  if (updates)
  {
    ski_registerUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
    ski_registerUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
    ski_registerUpdate(cache, &arrUpdateID[2][0], bgp_BGPsec_PATH[1]);
  }          
}

/**
 * Testing SKI_CLEAN_ALL
 * 
 * @param keyInfo (OUT) contains the cache info for keys only
 * @param updInfo (OUT) contains the cache info for updates only
 */
static void test_8a(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  test_8init("8a", "Testing SKI_CLEAN_ALL", true, true);
    
  // Do The Test
  ski_clean(cache, SKI_CLEAN_ALL);    
  SKI_CACHE_INFO info;
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  int count = info.count_AS2 + info.count_cAlgoID + info.count_cData 
              + info.count_cNode + info.count_cUID + info.count_keys
              + info.count_updates;
  assert_int(count, 0, "Expected to have all elements removed!");
  
  // Now the test passed, gather the info for key only and update only
  
  // KEY INFO
  test_8init(NULL, NULL, true, false);
  ski_examineCache(cache, keyInfo, verbose);
  ski_clean(cache, SKI_CLEAN_ALL);  

  // UPDATE INFO
  test_8init(NULL, NULL, false, true);
  ski_examineCache(cache, updInfo, verbose);
  ski_clean(cache, SKI_CLEAN_ALL);
  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Testing SKI_CLEAN_KEYS
 * 
 * @param keyInfo contains the cache info for keys only
 * @param updInfo contains the cache info for updates only
 */
static void test_8b(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  test_8init("8b", "Testing SKI_CLEAN_KEYS", true, true);

  // Examine the cache
  SKI_CACHE_INFO info;  
  ski_clean(cache, SKI_CLEAN_KEYS);

  ski_examineCache(cache, &info, verbose);  
  assert_info(&info, updInfo, "Expected to have no leftovers from key "
                              "registration");
  
  ski_clean(cache, SKI_CLEAN_ALL);  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Testing SKI_CLEAN_UPDATES
 * @param keyInfo contains the cache info for keys only
 * @param updInfo contains the cache info for updates only
 */
static void test_8c(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  test_8init("8c", "Testing SKI_CLEAN_UPDATES", true, true);

  SKI_CACHE_INFO info;
  ski_examineCache(cache, &info, verbose);
  int noKeys = info.count_keys;

  ski_clean(cache, SKI_CLEAN_UPDATES);

  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  assert_info(&info, keyInfo, "Expected to have no leftovers from update "
                              "registration");
  
  ski_clean(cache, SKI_CLEAN_ALL);  
  verbose = oldVerbose;
  printPassed();
}

/**
 * Testing SKI_CLEAN_NONE - Garbage collection from keys
 * 
 * @param keyInfo contains the cache info for keys only
 * @param updInfo contains the cache info for updates only
 */
static void test_8d(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  test_8init("8d", "Testing SKI_CLEAN_NONE - Garbage collection from KEYS", 
             true, true);

  SKI_CACHE_INFO info;
  
  // Unregister all Keys
  int idx = 0;
  TEST_SKI_DATA* data;
  for (; idx < noElements; idx++)
  {
    data = testData[idx];
    if (verbose)
    {
      printDataElement(data, " Unregister ");
    }
    ski_unregisterKey(cache, data->asn, data->ski, data->algoID);
  }
  // Garbage Collect
  ski_clean(cache, SKI_CLEAN_NONE);      
  // Examine the cache
  ski_examineCache(cache, &info, verbose);
  
  assert_info(&info, updInfo, "Expected all empty structures remaining from "
                              "keys be removed");  
  
  ski_clean(cache, SKI_CLEAN_ALL);
  verbose = oldVerbose;
  printPassed();
}

/**
 * Testing SKI_CLEAN_NONE - Garbage collection from updates
 * 
 * @param keyInfo contains the cache info for keys only
 * @param updInfo contains the cache info for updates only
 */
static void test_8e(SKI_CACHE_INFO* keyInfo, SKI_CACHE_INFO* updInfo)
{
  bool oldVerbose = verbose;
  verbose = verbose || checkVerbose(__func__);

  test_8init("8e", "Testing SKI_CLEAN_NONE - Garbage collection from KEYS", 
             true, true);

  ski_unregisterUpdate(cache, &arrUpdateID[0][0], bgp_BGPsec_PATH[0]);
  ski_unregisterUpdate(cache, &arrUpdateID[1][0], bgp_BGPsec_PATH[1]);
  ski_unregisterUpdate(cache, &arrUpdateID[2][0], bgp_BGPsec_PATH[1]);  
  
  SKI_CACHE_INFO info;
  // Examine the cache
  // Garbage Collect
  ski_clean(cache, SKI_CLEAN_NONE);      
  // Examine the cache
  ski_examineCache(cache, &info, verbose);  
  assert_info(&info, keyInfo, "Expected all empty structures remaining from "
                              "keys be removed");  
  
  ski_clean(cache, SKI_CLEAN_ALL);
  verbose = oldVerbose;
  printPassed();
}

////////////////////////////////////////////////////////////////////////////////
// MAIN METHOD
////////////////////////////////////////////////////////////////////////////////

/**
 * Print program syntax and exit
 */
void syntax()
{
  printf ("Syntax: test_ski_cache [-v] [-noExit]\n\n");
  
  printf ("  Options:\n");
  printf ("     -v        Verbose output\n");
  printf ("     -noExit   Prevent tester to exit when a test failed!\n\n");
  printf ("2017 by Oliver Borchert (borchert@nist.gov)\n");
          
  exit (EXIT_SUCCESS);
}

/* 
 * Parse the program arguments and set basic parameters.
 */
void parseArguments(int argc, char** argv)
{
  int idx = 1;
  for (; (idx < argc); idx++)
  {
    if (strcasecmp(argv[idx], "-?") == 0)
    {
      syntax();
    }
    else if (strcasecmp(argv[idx], "-v") == 0)
    {
      verbose = true;
    }
    else if (strcasecmp(argv[idx], "-noExit") == 0)
    {
      exitOnAssertFailure = false;
    }
    else
    {
      noElements = atoi(argv[idx]);
    }
  }
  if (noElements != 0)
  {  
    if (noElements > MAX_NO_ELEMENTS)
    {
      printf("provided number of elements too large, reduce to %u\n", 
             MAX_NO_ELEMENTS);
      noElements = MAX_NO_ELEMENTS;    
    }
  }
  else
  {
    noElements = MAX_NO_ELEMENTS;
  }  
}

/**
 * The main test method
 */
int main(int argc, char** argv) 
{
  // Global variables
  rpki_queue = rq_createQueue();  
  cache      = ski_createCache(rpki_queue);
  noElements = 0;
   
  
  parseArguments(argc, argv);  
  
  printf ("Create test vectors for SKI - Key and Update testing!\n");
  createTestData(false);
  
  printf ("Do SKI Cache Testing.\n");
  // Test the registration and removal of keys using empty cache
  //test_1();
  // Test the registration and removal of BGPsec UPDATES using empty cache
  test_2();
  // Using one key and one update that requires the key, this test tests the
  // notification mechanism using the RPKI Queue
  test_3();
  // Using 2 updates and 8 keys, this test simulates adding and removing of 
  // keys with different filling states of the ski cache.
  test_4();                         
  // Test removing updates and keys that are not previously stored on empty 
  // cache
  test_5();
  // Test removing updates and keys that are not previously stored a cache 
  // previously filled with other data
  test_6();
  // Test the correct counting of update registrations.
  test_7();
  // Test the clean methods
  test_8();
  
  printf ("Release test vectors for SKI - Key and Update testing!\n");
  // Clean up Test Data
  freeTestData();  
  // release cache and queue
  ski_releaseCache(cache);  
  rq_releaseQueue(rpki_queue);
  
  return (EXIT_SUCCESS);
}