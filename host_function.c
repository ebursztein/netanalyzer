/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/*!	
 *	\file host_function.c
 *	\brief functions used to hosts tracking and displaying.
 *
 *	This file contains every functions related to host handeling. It's also linked to 
 *	gateway detection.
 *	\author  Elie
 *	\version 1.1
 *	\date    September 2006
 *	\bug
 *	\todo output ?
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
extern	t_hash		*hosts;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_benchmark	bench;
extern	t_mutex		mutex;

t_host	**hosts_list;
_u64	host_id; ///!< used to give an uniq numeric identificator to each host
//inner function
int	host_add(t_host *h);
t_host 	*host_free(t_host *h);
t_host 	*host_from_pkt(t_pkt *p, _u32 way);
t_host 	*host_exist(t_host *h);
t_host 	*host_update(t_host *h, t_host *new);
t_host	*host_from_ip(_u32	ip);
//main function entry
_u32 analyze_host(t_pkt *p, _u8 update)
{		
	t_host	*from;
	t_host	*to;
	t_host	*h;
	//fixme none ip network
	if (p->pkt_proto >= IP)
	{
		from = host_from_pkt(p, HOST_FROM);
		if (update == NEWCONN)
			from->conn_out++;
		if ((h = host_exist(from)) != NULL)
		{
			host_update(h, from);
			p->s->src_host_id 	= h;
			p->s->client_id 		= h->id;
		} else {
			host_add(from);
			p->s->src_host_id 	= from;
			p->s->client_id 		= from->id;
		}
		to = host_from_pkt(p, HOST_TO);
		if (update == NEWCONN)
			to->conn_in++;
		if ((h = host_exist(to)) != NULL)
		{
			host_update(h, to);
			p->s->dst_host_id 	= h;
			p->s->server_id 	= h->id;
		}
		else
		{
			host_add(to);
			p->s->dst_host_id 	= to;
			p->s->server_id 	= to->id;
		}
	}
	return 0;
}

static _u32 host_key(_u32 ip)
{
	_u32 key = 32;
	key += ip;
	return key;	
}

void host_set_option(_u32 ip, _u32 opt)
{
	_u32 		k, kindex;
	t_hash_entry 	*e;
	t_host		*h;
	k = host_key(ip);
	kindex = hash_indexFor(hosts->tablelength, k);
	if(option.debug == 10)
		printf("%u set option %d\n", ip, opt);
	e = hosts->table[kindex];
	while (NULL != e)
	{
		if (e->h->ip == ip)
		{
			e->h->infos = e->h->infos | opt;

			return;
		}
		e = e->next;
	}
	//not found need to add it
	h = host_from_ip(ip);
	h->infos = h->infos | opt;
	host_add(h);
	return;
}


_u32 host_is_equal(t_host *h1, t_host *h2)
{
	
	assert(h1 != NULL);
	assert(h2 != NULL);
	//_u32 timeout = 0;
	///!\todo fixeme timeout
	if (h1->ip != h2->ip)
		return 0;
	else
		return 1;
}


t_hash *host_init(void)
{
	t_hash *h;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	h = (t_hash *)malloc(sizeof(t_hash));
	if (h == NULL) 
		return NULL; /*oom*/
	// ** for table of pointer
	h->table = (t_hash_entry **)malloc(sizeof(t_hash_entry) * size);
	if (NULL == h->table) { 
		free(h); 
		warning("host hash table allocation failed");
		return NULL; } /*oom*/
		
	bzero(h->table, size * sizeof(t_hash_entry *));
	h->tablelength  = size;
	h->primeindex   = pindex;
	h->type		= HASH_HOST;
	h->entrycount   = 0;
	return h;
}

t_host *host_update(t_host *h, t_host *new)
{
	_u32 i;
	h->last_time = new->last_time;
	h->sanity    = h->sanity | new->sanity;
	
	for (i = 0; i < 255; i++)
		if (new->ttl[i])
			h->ttl[i]++;
	//fixme trop chelou
	if ((memcmp(h->arp,new->arp, ETHER_ALEN)))
	{
		h->arp_flip++;
		memcpy(h->arp, new->arp, ETHER_ALEN);		
	}

	//stats update
	h->bytes_in	+= new->bytes_in;
	h->bytes_out	+= new->bytes_out;
	h->nb_pkt_in	+= new->nb_pkt_in;
	h->nb_pkt_out	+= new->nb_pkt_out;
	h->request	+= new->request;
	h->reply	+= new->reply;
	h->error	+= new->error;
	h->conn_in	+= new->conn_in;
	h->conn_out	+= new->conn_out;
	free(new);
	new = 0;
	return h;
}

t_host *host_exist(t_host *h)
{
	assert(h != NULL);
	_u32 		k, kindex;
	t_hash_entry 	*e;
	k = host_key(h->ip);
	kindex = hash_indexFor(hosts->tablelength, k);
	e = hosts->table[kindex];
	while (NULL != e)
	{
		if(e->h == NULL)
			die ("hash not void but host yes shoud never  happend\n");
		if (host_is_equal(e->h, h)) 
			return e->h;
		e = e->next;
	}
	return NULL;
}


t_host	*host_from_ip(_u32 ip)
{
	t_host	*h; 
	h = (t_host *)malloc(sizeof(t_host));
	bzero(h, sizeof(t_host));
	h->ip =  ip;
	return h;
}


t_host *host_from_pkt(t_pkt *p, _u32 way)
{
	t_host	*h; 
	//init session
	h = (t_host *)malloc(sizeof(t_host));
	bzero(h, sizeof(t_host));
	if (p->pkt_proto > IP)
		h->ttl[p->ip->ttl] = 1;
	h->last_time = p->time_capture;
	
	if (way == HOST_FROM)
	{
		if (p->pkt_proto > IP)		
			h->ip         = p->ip->src;
		h->bytes_out  = p->len;
		h->nb_pkt_out = 1;
		//love mac starting by \0 
		memcpy(h->arp, p->ether->shost, ETHER_ALEN);
	} else {
		if (p->pkt_proto > IP)
			h->ip         = p->ip->dst;
		h->bytes_in   = p->len;
		h->nb_pkt_in  = 1;
		memcpy(h->arp, p->ether->dhost, ETHER_ALEN);	
	} 
	h->ethervendor = macprefix_get_vendor_by_arp(h->arp);
	return h;
}

//just freeing the entry
t_host *host_free(t_host *h)
{
	free(h);
	h = NULL;
	return NULL;
}
int host_add(t_host *host)
{
	t_hash_entry	*h;
	_u32		k;
	assert(host != NULL);
	//assigning uniq id
	bench.host_id++;
	host->id = bench.host_id;
	if (option.debug == 10)
		printf("Host id %lld add %d (%d/%d) coll %d\n",host->id, host->ip, hosts->entrycount, hosts->tablelength, hosts->collision);
	h = (t_hash_entry *)malloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = host_key(host->ip);
	//adding key to hash entry for table resize
	h->k = k;
	//clipping session to hash entry
	h->h =	host;
	//clipping entry to hash table
	pthread_mutex_lock(&mutex.hashhost);
	add_hash(hosts, k, h);
	pthread_mutex_unlock(&mutex.hashhost);
	return 1;
}


//Sort the hash table for displaying and stating
void host_sorting()
{
	_s32		i,j;
	t_hash_entry 	*e;
	analyze.host_stated = hosts->entrycount;
	//printf("\n------\nHost entrycount %d last host_id %lld tablelength %d\n------\n", hosts->entrycount, bench.host_id, hosts->tablelength);
	if (hosts->entrycount < 0 || analyze.host_stated < 0 )
		die("Na can't happend host->entrycount is %d, host_stated is %d", hosts->entrycount, analyze.host_stated);
	if (hosts_list)
		free(hosts_list);
	hosts_list = (t_host **)xmalloc(sizeof(t_host*) * analyze.host_stated);
	bzero(hosts_list, sizeof(t_host*) * analyze.host_stated);
	
	for(j = 0, i = hosts->tablelength; i--;)
	{
		e = hosts->table[i];
		while (NULL != e)
		{
			hosts_list[j] = e->h;
			e = e->next;
			j++;
			//be aware of multithread .. host may have been added during the function
			if (j == analyze.host_stated)
				return;
		}
	}

}





void host_clean()
{
	_u32		i;
	_u32		t;
	_u32		count;
	t = time(NULL);
	t_hash_entry 	*e, *tmp, *pred;
 	t_hash_entry 	**pE;
	pred = NULL;
	for(i = hosts->tablelength; i--;)
	{
		//e = hosts->table[i];
		pE = &(hosts->table[i]);
    		e = *pE;
		count = 0;
		while (NULL != e)
		{
			assert(e->h != NULL);
			if(e->h->last_time + option.intervall < t)
			{
				tmp = e;
				//printf("I want to shoot %lld position %d\n",e->h->id, count);
				
				*pE = e->next;
				e = e->next;
				free(tmp->h);
				free(tmp);
				
				hosts->entrycount--;
				 if (pred != NULL) 			pred->next = e;
			//	else if (count == 0 && e == NULL)  	hosts->table[i] = NULL;//this cell is empty -> global modification
			//	else if (count == 0 && e != NULL)  	hosts->table[i] = e;//this cell first element is out -> global modification
			//continue;
		
			} else {
				count++;
				e->h->conn_in 		= 0;
				e->h->conn_out		= 0;
				e->h->nb_pkt_in		= 0;
				e->h->nb_pkt_out	= 0;
				e->h->bytes_in		= 0;
				e->h->bytes_out		= 0;
				e->h->request		= 0;
				e->h->reply		= 0;
				e->h->error		= 0;
				pred = e;
				//
				pE = &(e->next);
        			e = e->next;
			}
		}
	}
}

