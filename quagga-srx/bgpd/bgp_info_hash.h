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
 * Various function to make debugging easier.
 *
 * @version 0.3.1.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.3.1.0 - 2015/11/26 - oborchert
 *            * Added Changelog
 *            * Changed include of uthash.h from local to stock
 */
#include <zebra.h>

#ifndef _QUAGGA_BGP_INFO_HASH_H
#define _QUAGGA_BGP_INFO_HASH_H

#ifdef USE_SRX

#include <uthash.h>

struct bgp_info_hash_item {
  uint32_t        identifier;
  struct bgp_info *info;
  UT_hash_handle  hh;
};

struct bgp_info_hash {
  struct bgp_info_hash_item *table;
};


/* Install VTY commands - call only once */
extern void bgp_all_info_hashes_init (void);

/* Create and destroy a info hash */
extern struct bgp_info_hash* bgp_info_hash_init (void);
extern void bgp_info_hash_finish (struct bgp_info_hash **);

/* Access the hash */
/* 1 = registered, 0 = known identifier, -1 = error */
extern int bgp_info_register (struct bgp_info_hash *, struct bgp_info *,
                              uint32_t);
extern void bgp_info_unregister (struct bgp_info_hash *, uint32_t);
extern struct bgp_info * bgp_info_fetch (struct bgp_info_hash *, uint32_t);

#endif /* USE_SRX */

#endif /* !_QUAGGA_BGP_INFO_HASH_H */

