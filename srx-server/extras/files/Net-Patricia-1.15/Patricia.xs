#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include "libpatricia/patricia.h"

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    case 'A':
	break;
    case 'B':
	break;
    case 'C':
	break;
    case 'D':
	break;
    case 'E':
	break;
    case 'F':
	break;
    case 'G':
	break;
    case 'H':
	break;
    case 'I':
	break;
    case 'J':
	break;
    case 'K':
	break;
    case 'L':
	break;
    case 'M':
	break;
    case 'N':
	break;
    case 'O':
	break;
    case 'P':
	break;
    case 'Q':
	break;
    case 'R':
	break;
    case 'S':
	break;
    case 'T':
	break;
    case 'U':
	break;
    case 'V':
	break;
    case 'W':
	break;
    case 'X':
	break;
    case 'Y':
	break;
    case 'Z':
	break;
    case 'a':
	break;
    case 'b':
	break;
    case 'c':
	break;
    case 'd':
	break;
    case 'e':
	break;
    case 'f':
	break;
    case 'g':
	break;
    case 'h':
	break;
    case 'i':
	break;
    case 'j':
	break;
    case 'k':
	break;
    case 'l':
	break;
    case 'm':
	break;
    case 'n':
	break;
    case 'o':
	break;
    case 'p':
	break;
    case 'q':
	break;
    case 'r':
	break;
    case 's':
	break;
    case 't':
	break;
    case 'u':
	break;
    case 'v':
	break;
    case 'w':
	break;
    case 'x':
	break;
    case 'y':
	break;
    case 'z':
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

#define Fill_Prefix(p,f,a,b,mb) \
	do { \
		if (b < 0 || b > mb) \
		  croak("invalid key"); \
		memcpy(&p.add.sin, a, (mb+7)/8); \
		p.family = f; \
		p.bitlen = b; \
		p.ref_count = 0; \
	} while (0)

static void deref_data(SV *data) {
   SvREFCNT_dec(data);
   data = (void *)0;
}

static size_t
patricia_walk_inorder_perl(patricia_node_t *node, SV *coderef) {
    dSP;
    size_t n = 0;

    if (node->l) {
         n += patricia_walk_inorder_perl(node->l, coderef);
    }

    if (node->prefix) {
        if ((SV *)0 != coderef) {
            PUSHMARK(SP);
            XPUSHs(sv_mortalcopy((SV *)node->data));
            PUTBACK;
            perl_call_sv(coderef, G_VOID|G_DISCARD);
            SPAGAIN;
        }
	n++;
    }
	
    if (node->r) {
         n += patricia_walk_inorder_perl(node->r, coderef);
    }

    return n;
}

typedef patricia_tree_t *Net__Patricia;
typedef patricia_node_t *Net__PatriciaNode;

MODULE = Net::Patricia		PACKAGE = Net::Patricia

PROTOTYPES: ENABLE

double
constant(name,arg)
	char *		name
	int		arg

Net::Patricia
_new(size)
	int				size
	CODE:
		RETVAL = New_Patricia(size);
	OUTPUT:	
		RETVAL

void
_add(tree, family, addr, bits, data)
	Net::Patricia			tree
	int				family
	char *				addr
	int				bits
	SV *				data
	PROTOTYPE: $$$$$
	PREINIT:
	   	prefix_t prefix;
	   	Net__PatriciaNode node;
	PPCODE:
		Fill_Prefix(prefix, family, addr, bits, tree->maxbits);
	   	node = patricia_lookup(tree, &prefix);
		if ((patricia_node_t *)0 != node) {
		   /* { */
		   if (node->data) {
		      deref_data(node->data);
		   }
		   node->data = newSVsv(data);
		   /* } */
		   PUSHs(data);
		} else {
		   XSRETURN_UNDEF;
		}

void
_match(tree, family, addr, bits)
	Net::Patricia			tree
	int				family
	char *				addr
	int				bits
	PROTOTYPE: $$$$
	PREINIT:
	   	prefix_t prefix;
	   	Net__PatriciaNode node;
	PPCODE:
		Fill_Prefix(prefix, family, addr, bits, tree->maxbits);
		node = patricia_search_best(tree, &prefix);
		if ((patricia_node_t *)0 != node) {
		   XPUSHs((SV *)node->data);
		} else {
		   XSRETURN_UNDEF;
		}

void
_exact(tree, family, addr, bits)
	Net::Patricia			tree
	int				family
	char *				addr
	int				bits
	PROTOTYPE: $$$$
	PREINIT:
	   	prefix_t prefix;
	   	Net__PatriciaNode node;
	PPCODE:
		Fill_Prefix(prefix, family, addr, bits, tree->maxbits);
		node = patricia_search_exact(tree, &prefix);
		if ((patricia_node_t *)0 != node) {
		   XPUSHs((SV *)node->data);
		} else {
		   XSRETURN_UNDEF;
		}


void
_remove(tree, family, addr, bits)
	Net::Patricia			tree
	int				family
	char *				addr
	int				bits
	PROTOTYPE: $$$$
	PREINIT:
	   	prefix_t prefix;
	   	Net__PatriciaNode node;
	PPCODE:
		Fill_Prefix(prefix, family, addr, bits, tree->maxbits);
	   	node = patricia_search_exact(tree, &prefix);
		if ((Net__PatriciaNode)0 != node) {
		   XPUSHs(sv_mortalcopy((SV *)node->data));
		   deref_data(node->data);
		   patricia_remove(tree, node);
		} else {
		   XSRETURN_UNDEF;
		}

size_t
climb(tree, ...)
	Net::Patricia			tree
	PREINIT:
		patricia_node_t *node = (patricia_node_t *)0;
		size_t n = 0;
		SV *func = (SV *)0;
	CODE:
		if (2 == items) {
		   func = ST(1);
		} else if (2 < items) {
	           croak("Usage: Net::Patricia::climb(tree[,CODEREF])");
		}
		PATRICIA_WALK (tree->head, node) {
		   if ((SV *)0 != func) {
		      PUSHMARK(SP);
		      XPUSHs(sv_mortalcopy((SV *)node->data));
		      PUTBACK;
		      perl_call_sv(func, G_VOID|G_DISCARD);
		      SPAGAIN;
		   }
		   n++;
		} PATRICIA_WALK_END;
		RETVAL = n;
	OUTPUT:	
		RETVAL

size_t
climb_inorder(tree, ...)
	Net::Patricia			tree
	PREINIT:
		size_t n = 0;
		SV *func = (SV *)0;
	CODE:
		func = (SV *)0;
		if (2 == items) {
		   func = ST(1);
		} else if (2 < items) {
	           croak("Usage: Net::Patricia::climb_inorder(tree[,CODEREF])");
		}
                n = patricia_walk_inorder_perl(tree->head, func);
		RETVAL = n;
	OUTPUT:	
		RETVAL

void
DESTROY(tree)
	Net::Patricia			tree
	CODE:
	Destroy_Patricia(tree, deref_data);
