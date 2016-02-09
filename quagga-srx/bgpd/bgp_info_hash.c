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
 */
#include <zebra.h>

#ifdef USE_SRX

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "vty.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_info_hash.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"

#define SHOW_SCODE_HEADER "Validation code: v valid, n notfound, i invalid, ? undefined%s%s"
#define SHOW_HEADER "         Ident          Network       I LocPrf Path%s"

static int show_info_hash (struct vty* vty, struct bgp* bgp, 
                           struct bgp_info_hash *hash)
{
  static const char RES_CODE_CHAR[] = { 'v', 'n', 'i', '?' };

  struct bgp_info_hash_item* curr;
  char pbuf[INET6_ADDRSTRLEN];
  struct attr* attr;
  int valState;
  
  if (HASH_COUNT (hash->table) == 0)
  {
    vty_out (vty, "   (No entries)%s%s", VTY_NEWLINE, VTY_NEWLINE);
    return 0;
  }

  vty_out (vty, SHOW_HEADER, VTY_NEWLINE);
  for (curr = hash->table; curr != NULL; curr = curr->hh.next)
  {
    valState = srx_calc_validation_state(bgp, curr->info);
    vty_out (vty, "   %c(%c%c) %08X ", 
        RES_CODE_CHAR[valState],             
        RES_CODE_CHAR[curr->info->val_res_ROA],
        RES_CODE_CHAR[curr->info->val_res_BGPSEC],
        curr->identifier);

    /* Node - identified by its prefix */
    if (curr->info->node)
    {
      vty_out (vty, "%15s/%-2d  ",
               inet_ntop (curr->info->node->p.family, 
                          &curr->info->node->p.u.prefix, 
                          pbuf, INET6_ADDRSTRLEN),
        curr->info->node->p.prefixlen);
    }
    else
    {
      vty_out (vty, "(NULL node)         ");
    }

    /* Ignore flag */
    if (CHECK_FLAG (curr->info->flags, BGP_INFO_IGNORE))
    {
      vty_out (vty, "x ");
    }
    else
    {
      vty_out (vty, "  ");
    }

    attr = curr->info->attr;

    /* Local-preference and adjustment */
    if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    {
      vty_out (vty, "%d", attr->local_pref);
    }
    else
    {
      vty_out (vty, "D:%d", bgp->default_local_pref);
    }

    switch (valState)
    {
      case SRx_RESULT_VALID:
        valState = VAL_LOCPRF_VALID;
        break;
      case SRx_RESULT_NOTFOUND:
        valState = VAL_LOCPRF_NOTFOUND;
        break;
      case SRx_RESULT_INVALID:
        valState = VAL_LOCPRF_INVALID;
        break;
      case SRx_RESULT_UNDEFINED:
      default:
        valState = -1;
    }
    if (valState != -1)
    {
      if (bgp->srx_val_local_pref[valState].is_set)
      {
        if (bgp->srx_val_local_pref[valState].relative)
        {
          vty_out (vty, "%c%4d", 
                   (bgp->srx_val_local_pref[valState].relative == 1) ? '+' 
                                                                     : '-' ,
                    bgp->srx_val_local_pref[valState].value);
        }
        else
        {
          vty_out (vty, "->%4d", bgp->srx_val_local_pref[valState].value);
        }        
      }
    }
    else
    {
      vty_out (vty, "      ");
    }        

    /* AS-Path */
    if (attr->aspath)
    {
      aspath_print_vty (vty, " \"%s\"", attr->aspath, " ");
    }
 
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  vty_out (vty, "%s", VTY_NEWLINE);

  return 1;
}

/** Is not available in terminal session. */
DEFUN (show_bgp_info_hashes,
       show_bgp_info_hashes_cmd,
       "show bgp info-hashes",
       SHOW_STR
       BGP_STR
       "Display all info hashes\n")
{
  struct listnode* curr;
  struct bgp* bgp;

  vty_out (vty, SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO(bm->bgp, curr, bgp))
  {
    vty_out (vty, "BGP info hash UID of AS %d%s", bgp->as, VTY_NEWLINE);
    show_info_hash(vty, bgp, bgp->info_uid_hash);
    vty_out (vty, "BGP info hash LID of AS %d%s", bgp->as, VTY_NEWLINE);
    show_info_hash(vty, bgp, bgp->info_lid_hash);
  }

  return CMD_SUCCESS;
}

void bgp_all_info_hashes_init (void)
{
// remove this debug command!
// install_element (VIEW_NODE, &show_bgp_info_hashes_cmd);
}

struct bgp_info_hash* bgp_info_hash_init (void)
{
  struct bgp_info_hash* new;
  
  new = XCALLOC(MTYPE_BGP_INFO_HASH, sizeof(struct bgp_info_hash));
  if (new)
  {
    new->table = NULL;
  }
  return new;
}

void bgp_info_hash_finish (struct bgp_info_hash** hash)
{
  struct bgp_info_hash_item* curr;

  while ((*hash)->table)
  {
    curr = (*hash)->table;
    HASH_DEL ((*hash)->table, curr);
    XFREE (MTYPE_BGP_INFO_HASH_ITEM, curr);
  }

  XFREE (MTYPE_BGP_INFO_HASH, *hash);
  *hash = NULL;
}

/**
 * 
 * @param hash
 * @param info
 * @param identifier
 * 
 * @return 1 if the registration was successfull, 0 if the update identifier was
 *         already known to the system and -1 if an error occured.
 */
int bgp_info_register (struct bgp_info_hash* hash, struct bgp_info* info, 
                       uint32_t identifier)
{
  if (identifier == 0)
  {
    return 0;
  }
  
  struct bgp_info_hash_item *new;
  
  /* Add to the hash */
  new = XCALLOC (MTYPE_BGP_INFO_HASH_ITEM, sizeof(struct bgp_info_hash_item));
  if (new == NULL) 
  {
    zlog_err("Not enough memory to store update [0x%80X]", identifier);
    return -1;
  }

  new->identifier = identifier;
  new->info       = info;

  HASH_ADD(hh, hash->table, identifier, sizeof(uint32_t), new);

  info->info_hash = hash;

  return 1;
}

/**
 * Remove the update id <-> update relation from the hash table.
 * 
 * @param hash The hash table
 * @param identifier the update identifier who has to be removed.
 */
void bgp_info_unregister(struct bgp_info_hash* hash, uint32_t identifier)
{
  struct bgp_info_hash_item* entry;

  HASH_FIND(hh, hash->table, &identifier, sizeof(uint32_t), entry);
  if (entry)
  {
    HASH_DEL(hash->table, entry);
    XFREE(MTYPE_BGP_INFO_HASH, entry);
  }
}

/**
 * Retrieve the bgp update associated with the update id or NULL
 * 
 * @param hash the info hash table
 * @param identifier the update identifier
 * 
 * @return the bgp update or NULL
 */
struct bgp_info* bgp_info_fetch (struct bgp_info_hash* hash, 
                                 uint32_t identifier)
{
  struct bgp_info_hash_item* entry;
  
  HASH_FIND (hh, hash->table, &identifier, sizeof(uint32_t), entry);

  if(entry) 
  {
    for( entry= hash->table; entry!=NULL; 
         entry=(struct bgp_info_hash_item*)(entry->hh.next))
    {
      if (entry->identifier == identifier)
      {
        return entry->info;
      }
    }
  }
  return NULL;
}

#endif /* USE_SRX */

