/* 
 * File:   main.c
 * Author: borchert
 *
 * Created on August 4, 2015, 6:44 PM
 */

#include <stdio.h>
#include <stdlib.h>

#include "ASNTokenizer.h"

#define ASN_STR " 10 200 1.1 4 50   \0"

/*
 * 
 */
int main(int argc, char** argv) 
{
  u_int32_t asn = 0;
  asntok(ASN_STR);
  printf ("Separate an AS string [\"%s\"] into its ASN components.\n", ASN_STR);
  printf ("\nAS4 as Integer\n");
  while (asntok_next(&asn))
  {
    printf (" - AS %u\n", asn);
  }
  asntok_reset();
  printf ("\nAS4 with two 2 byte Integer separated by dot.\n");
  while (asntok_next(&asn))
  {
    printf (" - AS %u.%u\n", (asn >>16), (asn & 0xFFFF));
  }
  
  return (EXIT_SUCCESS);
}

