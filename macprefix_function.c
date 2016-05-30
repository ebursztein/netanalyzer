/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <netdb.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
extern	t_term_color	cl;
extern 	_u32 		primes[];
extern t_hash		*macprefix;
extern t_option		option;

static inline int macprefix_key(const _u8 *prefix) {
	return (prefix[0] << 16) + (prefix[1] << 8) + prefix[2];
}

t_hash *macprefix_init(void)
{
	t_hash *h;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	//init the session counter to 0
	h = (t_hash *)malloc(sizeof(t_hash));
	if (h == NULL) 
		return NULL; /*oom*/
	// ** for table of pointer
	h->table = (t_hash_entry **)malloc(sizeof(t_hash_entry) * size);
	if (NULL == h->table) { 
		free(h); 
		return NULL; } /*oom*/
		
		bzero(h->table, size * sizeof(t_hash_entry *));
		h->tablelength  = size;
		h->primeindex   = pindex;
		h->type		= HASH_MAC;
		h->entrycount   = 0;
		return h;
}

void macprefix_add(int prefix, char* vendor)
{
	t_hash_entry	*h;
	_u32		 k;
	t_macaddr	*m;
	
	m = (t_macaddr *)xmalloc(sizeof(t_macaddr));
	bzero(m, sizeof(t_macaddr));
	m->prefix = prefix;
	m->vendor = (char *)my_strndup(vendor, strlen(vendor));
	h = (t_hash_entry *)xmalloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	if (option.debug == 60)
		printf("Adding vendor %s for prefix %d\n", vendor, prefix);
	//compute hash key
	k = prefix;
	//adding key to hash entry for table resize
	h->k = k;
	//clipping session to hash entry
	h->m =	m;
	//clipping entry to hash table
	add_hash(macprefix, k, h);
}

char *macprefix_get_vendor_by_arp(_u8 *arp)
{
	_u32		k, index;
	t_hash_entry	*e;
	if(!arp)
		return NULL;
	//getting mac key
	k = macprefix_key(arp);
	index = hash_indexFor(macprefix->tablelength, k);
	e = macprefix->table[index];
	while (NULL != e)
	{
		if (e->m->prefix == k) 
			return e->m->vendor;
		e = e->next;
	}
	return NULL;
}

void macprefix_list()
{
	_u32		i;
	t_hash_entry 	*e;
	for(i = macprefix->tablelength; i--;)
	{
		e = macprefix->table[i];
		while (NULL != e)
		{
			printf("%d:%s\n",e->m->prefix,e->m->vendor);
			e = e->next;
		}
	}
}
