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
extern	t_hash		*softwares;
extern	t_option	option;
extern	t_analyze	analyze;
extern 	t_benchmark	bench;
extern	t_mutex		mutex;
	t_software	**softwares_list;

//function
t_software *software_exist(t_software *o);
int software_add(t_software *o);
t_software *software_update(t_software *o, t_software *new);

//main function entry
_u32 analyze_software(t_software *o)
{
	t_software *exist;
	_u64	hash 		= 0;
	_u64	hash_version 	= 0;

	assert(o);
	assert(o->ip);
	assert(o->port);
	
	//hash
	hash += crc(o->product);
	hash += crc(o->protocol);
	hash += crc(o->familly);
	hash += crc(o->ostype);
	hash += crc(o->info);
	hash += o->ip;
	hash += o->proto;
	
	//hash version
	hash_version = crc(o->version);
	
	o->crc = hash;
	o->crc_version = hash_version;
	o->conn = 1;
	if((exist = software_exist(o)) != NULL) {
		software_update(exist, o);
		return 0;
	} else {
		software_add(o);
		return 1;
	}
}


/*!
 * used to tell if two software structure are equal
 * @param o1 the fist soft
 * @param o2 the second soft 
 * @see software_exist()
 * @return  1 if they are the same 0 otherwise
 * \version 1
 * \date   jan  2007
 * \author Elie
 * \attention we do not take into account the port if it's a client software because it will cause collide behavior
 * \todo Use a CRC instead of strcmp for more speed and do we need to handle software timeout or do we have to detect that the machine has change ?
	
	Sort the test : fastest test first for optimisation	

 */

_u32 software_is_equal(t_software *o1, t_software *o2)
{	
	assert(o1 != NULL);
	assert(o2 != NULL);
	assert(o1->ip != 0);
	assert(o2->ip != 0);

	if(o1->type == SOFT_CLIENT)
	{
	 	     if (o1->ip != o2->ip) 			return 0;
		else if (o1->crc != o2->crc) 			return 0;
		else if (o1->crc_version != o2->crc_version) 	return 0;
		else 						return 1;
	} else {
		
		     if (o1->ip != o2->ip) 			return 0;
		else if (o1->crc != o2->crc) 			return 0;
		else if (o1->crc_version != o2->crc_version) 	return 0;
		else if (o1->port != o2->port) 			return 0;
		else 						return 1;
	}
	return 0;
}


/*!
 * used to initialize the software hash table
 * @param o1 the fist soft
 * @param o2 the second soft 
 * @see main()
 * @return  the hash table
 * \version 1
 * \date   jan  2007
 * \author Elie
 */

t_hash *software_init(void)
{

	t_hash *o;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	o = (t_hash *)xmalloc(sizeof(t_hash));
	if (o == NULL) 
		return NULL; 
	// ** for table of pointer
	o->table = (t_hash_entry **)malloc(sizeof(t_hash_entry) * size);
	if (NULL == o->table) { 
		free(o); 
		return NULL; } 
		
		bzero(o->table, size * sizeof(t_hash_entry *));
		o->tablelength  = size;
		o->primeindex   = pindex;
		o->type		= HASH_SOFTWARE;
		o->entrycount   = 0;
		return o;
}

/*!
 * used to check if a software is already present into the hast table
 * @param o1 the software to check
 * @see analyze_software()
 * @return  a pointer to the software is it exist or NULL otherwise
 * \version 1
 * \date   jan  2007
 * \author Elie	

 */

t_software *software_exist(t_software *o)
{
	_u32 		k, index;
	t_hash_entry 	*e;
	k = o->crc;
	index = hash_indexFor(softwares->tablelength, k);
	e = softwares->table[index];
	while (NULL != e)
	{
		assert(e->o);
		assert(e->o->ip);
		if (software_is_equal(o,e->o)) 
			return e->o;
		e = e->next;
	}
	return NULL;
}


/*!
 * add a software to the hast table
 * @param o1 the software to add
 * @see analyze_software()
 * @return  add_hash() value
 * \version 1
 * \date   nov  2006
 * \author Elie
 */
int software_add(t_software *o)
{

	t_hash_entry	*h;
	_u32		 k;
	
	assert(o);

	//assigning uniq id

	bench.software_id++;
	o->id = bench.software_id;
	if (option.debug == 12)
		printf("Software id %lld added %d:%s (%d/%d) coll %d\n",o->id, o->ip, o->product, softwares->entrycount, softwares->tablelength, softwares->collision);
	h = (t_hash_entry *)malloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = o->crc;
	//adding key to hash entry for table resize
	h->k = k;
	//clipping software to hash entry
	h->o =	o;
	assert(o->ip);
	//clipping entry to hash table
	pthread_mutex_lock(&mutex.hashsoftware);
	add_hash(softwares, k, h);
	pthread_mutex_unlock(&mutex.hashsoftware);
	return 1;

}


//just freeing the entry
t_software *software_free(t_software *o)
{

	free(o);
	o = NULL;
	return NULL;
}

t_software *software_update(t_software *o, t_software *new)
{
/*
	o->last_seen = new->last_seen;
	o->last_seen_usec = new->last_seen_usec;
	o->sanity    = o->sanity | o->sanity;
	//stats update
	o->bytes_in	+= new->bytes_in;
	o->bytes_out	+= new->bytes_out;
	o->nb_pkt_in	+= new->nb_pkt_in;
	o->nb_pkt_out	+= new->nb_pkt_out;
	o->request	+= new->request;
	o->reply	+= new->reply;
	o->error	+= new->error;
	o->conn		+= new->conn;
	new = 0;
	return o;
*/
	o->conn++;
	free(new);
	return NULL;
}


//Sort the hash table for displaying and stating
void software_sorting()
{

	_u32		i,j;
	t_hash_entry 	*e;
	analyze.software_stated = softwares->entrycount;
	if (softwares_list)
		free(softwares_list);
	softwares_list = (t_software **)malloc(sizeof(t_software*) * analyze.software_stated);
	bzero(softwares_list, sizeof(t_software*) * analyze.software_stated);
	for(j = 0, i = softwares->tablelength; i--;)
	{
		e = softwares->table[i];
		while (NULL != e)
		{
			softwares_list[j] = e->o;
			e = e->next;
			j++;
			//be aware of multithread .. host may have been added during the function
			if (j == analyze.software_stated)
				return;
		}
	}


}

void software_clean()
{
	_u32		i;
	_u32		t;
	t = time(NULL);
	t_hash_entry 	*e, *tmp;
	 t_hash_entry 	**pE;
	for(i = softwares->tablelength; i--;)
	{
		pE = &(softwares->table[i]);
    		e = *pE;
		while (NULL != e)
		{
			if(e->o->last_seen + option.intervall < t)
			{
				tmp = e;
				*pE = e->next;
				e = e->next;
				free(tmp->o);
				free(tmp);
				softwares->entrycount--;
				continue;
			} else {
				///!\todo fixe me cleanup 
				pE = &(e->next);
				e = e->next;
			}
		}
	}
}
