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
extern	t_hash		*users2users;
extern	t_option	option;
extern	t_analyze	analyze;
extern 	t_benchmark	bench;
extern	t_mutex		mutex;
	t_user_to_user	**users2users_list;

//function
t_user_to_user *user2user_exist(t_user_to_user *u);
int user2user_add(t_user_to_user *u);
t_user_to_user *user2user_update(t_user_to_user *u, t_user_to_user *new);

//main function entry
_u32 analyze_user2user(t_user_to_user *u)
{
	t_user_to_user *exist;
	_u64	hash = 0;
	assert(u);
	assert(u->sender);
	assert(u->receiver);
	//hash
	hash += crc(u->sender);
	hash += crc(u->receiver);
	hash += crc(u->protocol);
	//clipping it
	u->crc = hash;
	
	if((exist = user2user_exist(u)) != NULL) {
		user2user_update(exist, u);
		return 0;
	} else {
		user2user_add(u);
		return 1;
	}
}



/*!
 * used to tell if two users2users structure are equal
 * @param u1 the fist relation
 * @param u2 the second relation
 * @see user_exist()
 * @return  1 if they are the same 0 otherwise
 * \version 1
 * \date   Feb  2007
 * \author Elie	
	Sort the test : fastest test first for optimisation	
 */

_u32 user2user_is_equal(t_user_to_user *u1, t_user_to_user *u2)
{	
	assert(u1 != NULL);
	assert(u2 != NULL);
	
	     if (u1->crc != u2->crc) return 0;
	else if (strcmp(u1->sender, u2->sender) != 0) return 0;
	else if (strcmp(u1->receiver,  u2->receiver) != 0) return 0;
	else if (strcmp(u1->protocol,  u2->protocol) != 0) return 0;
	else return 1;
}


/*!
 * used to initialize the user2user hashtable
 * @param o1 the fist soft
 * @param o2 the second soft 
 * @see main()
 * @return  the hash table
 * \version 1
 * \date   jan  2007
 * \author Elie
 */

t_hash *user2user_init(void)
{

	t_hash *o;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	//init user id 
	bench.user_id = 0;
	o = (t_hash *)xmalloc(sizeof(t_hash));
	if (o == NULL) 
		return NULL; 
	// ** for table of pointer
	o->table = (t_hash_entry **)malloc(sizeof(t_hash_entry) * size);
	if (NULL == o->table) { 
		warning("Hash table user2user cant be malloced\n");
		free(o); 
		return NULL; } 
		
		bzero(o->table, size * sizeof(t_hash_entry *));
		o->tablelength  = size;
		o->primeindex   = pindex;
		o->type		= HASH_USER_TO_USER;
		o->entrycount   = 0;
		return o;
}

/*!
 * used to check if a user2user is already present into the hasttable
 * @param u the user2user to test
 * @see analyze_user()
 * @return  a pointer to the user if it exists NULL otherwise
 * \version 1
 * \date   Feb  2007
 * \author Elie	

 */

t_user_to_user *user2user_exist(t_user_to_user *u)
{
	_u32 		k, indexe;
	t_hash_entry 	*e;
	k = u->crc;
	indexe = hash_indexFor(users2users->tablelength, k);
	e = users2users->table[indexe];
	while (NULL != e)
	{
		if (user2user_is_equal(u,e->r)) 
			return e->r;
		e = e->next;
	}
	return NULL;
}


/*!
 * add a user2user to the hasttable
 * @param u the user2user to add
 * @see analyze_user2user()
 * @return  add_hash() value
 * \version 1
 * \date   Feb  2007
 * \author Elie
 */
int user2user_add(t_user_to_user *u)
{

	t_hash_entry	*h;
	_u32		 k;
	
	assert(u);
	//assigning uniq id

	bench.u2u_id++;
	u->id = bench.user_id;
	if (option.debug == 15)
		printf("USER id %lld added %s->%s (%d/%d) coll %d\n",u->id, u->sender, u->receiver, users2users->entrycount, users2users->tablelength, users2users->collision);
	h = (t_hash_entry *)malloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = u->crc;
	//adding key to hash entry for table resize
	h->k = k;
	//clipping user to hash entry
	h->r =	u;
	//clipping entry to hash table
	pthread_mutex_lock(&mutex.hashuser2user);
	add_hash(users2users, k, h);
	pthread_mutex_unlock(&mutex.hashuser2user);
	return 1;

}


/*!
 * Free a user2user structure
 * @param u the user to free
 * @return  Null
 * \version 1
 * \date   Feb 2007
 * \author Elie
 */
t_user_to_user *user2user_free(t_user_to_user *u)
{

	free(u);
	u = NULL;
	return NULL;
}
/*!
 * update user2user  structure
 * @param u the structure to update
 * @param new the new information
 * @see analyze_user()
 * @return  user structure
 * \version 1
 * \date   Feb  2007
 * \author Elie
 */
t_user_to_user *user2user_update(t_user_to_user *u, t_user_to_user *new)
{	
	u->frequency++;
	u->last_time = new->last_time;
	u->last_time_usec = new->last_time_usec;
	user2user_free(new);
	return NULL;
}



//Sort the hash table for displaying and stating
void user2user_sorting()
{

	_s32		i,j;
	t_hash_entry 	*e;
	analyze.user2user_stated = users2users->entrycount;
	if (users2users_list)
		free(users2users_list);
	users2users_list = (t_user_to_user **)malloc(sizeof(t_user_to_user *) * analyze.user2user_stated);
	bzero(users2users_list, sizeof(t_user_to_user*) * analyze.user2user_stated);
	for(j = 0, i = users2users->tablelength; i--;)
	{
		e = users2users->table[i];
		while (NULL != e)
		{
			users2users_list[j] = e->r;
			e = e->next;
			j++;
			//be aware of multithread .. host may have been added during the function
			if (j == analyze.user2user_stated)
				return;
		}
	}


}


void user2user_clean()
{
	_u32		i;
	_u32		t;
	t = time(NULL);
	t_hash_entry 	*e, *tmp;
	t_hash_entry 	**pE;

	for(i = users2users->tablelength; i--;)
	{
		pE = &(users2users->table[i]);
    		e = *pE;
		while (NULL != e)
		{
			if(e->r->last_time + option.intervall < t)
			{
				tmp = e;
				*pE = e->next;
				e = e->next;
				free(tmp->r);
				free(tmp);
				users2users->entrycount--;
			} else {
				pE = &(e->next);
        			e = e->next;
			}
		}
	}
}
