#ifndef _QUAGGA_BGP_INFO_HASH_H
#define _QUAGGA_BGP_INFO_HASH_H

#ifdef USE_SRX

#include "srx/uthash.h"

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

