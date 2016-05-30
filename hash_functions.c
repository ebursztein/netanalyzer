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

#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"

extern t_option option;

/*
Credit for primes table: Aaron Krowne
 http://br.endernet.org/~akrowne/
 http://planetmath.org/encyclopedia/GoodHashTablePrimes.html
*/

//common part for all datas set (hash tables)
_u32 primes[] = {
53, 97, 193, 389,
769, 1543, 3079, 6151,
12289, 24593, 49157, 98317,
196613, 393241, 786433, 1572869,
3145739, 6291469, 12582917, 25165843,
50331653, 100663319, 201326611, 402653189,
805306457, 1610612741
};

_u32 prime_table_length = sizeof(primes)/sizeof(primes[0]);
/* indexFor */
_u32 hash_indexFor(_u32 tablelength, _u32 hashvalue) {
    return (hashvalue % tablelength);
};


static _u32 hashtable_expand(t_hash *h)
{
	/* Double the size of the table to accomodate more entries */
	t_hash_entry **newtable;
	t_hash_entry *e;
	_u32 newsize = 0, i, indexe;
	
	assert(h);
	assert(h->table);
	assert(h->tablelength);
	/* Check we're not hitting max capacity */
	if (h->primeindex == (prime_table_length - 1))
		return 0;
	
	newsize = primes[++(h->primeindex)];
	if(option.debug == 3)
		printf("resizing hash table from %d to %d\n",h->tablelength, newsize);
	newtable = (t_hash_entry **)malloc(sizeof(t_hash_entry*) * newsize);
	if (NULL != newtable)
	{
		//reseting collision
		h->collision = 0;
		memset(newtable, 0, newsize * sizeof(t_hash_entry *));
        /* This algorithm is not 'stable'. ie. it reverses the list
	* when it transfers entries between the tables */
		for (i = 0; i < h->tablelength; i++) {
			while (NULL != (e = h->table[i])) {
				h->table[i] = e->next;
				indexe = hash_indexFor(newsize,e->k);
				if (newtable[indexe])
					h->collision++;
				e->next = newtable[indexe];
				newtable[indexe] = e;
			}
		}
		free(h->table);
		h->table = newtable;
	}
	h->tablelength = newsize;
	return 1;
}



//add to hash : insert data at key pos in list
int add_hash(t_hash *list, _u32 key, t_hash_entry *data)
{
	/* This method allows duplicate keys - but they shouldn't be used */
	_u32 indexe;
	float load = HASH_LOAD;
	if (option.debug == 3)
		printf("%u hash add %u (%u/%u) coll %d\n",list->type, key, list->entrycount, list->tablelength, list->collision);
	if (((float)(++(list->entrycount)) / list->tablelength)> load)
		/* if no room get more, if more fail pray there is room for 1 element amen*/
		hashtable_expand(list);
	indexe = hash_indexFor(list->tablelength,key);
	//head insert (quickest)
	if (list->table[indexe])
		list->collision++;
	data->next = list->table[indexe];
	list->table[indexe] = data;
	return 1;
}

//remove from hash : delete data at key pos from list
/*int del_hash(t_hash *list, _u32 key, t_hash_entry *data)
{

	return 1;
}
*/

