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
#include <assert.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"

extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*users;
extern	t_option	option;
extern	t_analyze	analyze;
extern 	t_benchmark	bench;
extern	t_mutex		mutex;
	t_user		**users_list;

//function
t_user *user_exist(t_user *u);
int user_add(t_user *u);
t_user *user_update(t_user *u, t_user *new);

//main function entry
_u32 analyze_user(t_user *u)
{
	t_user *exist;
	_u64	hash = 0;
	assert(u);
	assert(u->ip);
	//hash
	hash += crc(u->login);
	hash += crc(u->pass);
	hash += crc(u->algorithm);
	hash += crc(u->additionnal);
	hash += crc(u->origin);
	hash += u->ip;
	//clipping it
	u->crc = hash;
	assert(u->crc != 0);
	if((exist = user_exist(u)) != NULL) {
		user_update(exist, u);
		return 0;
	} else {
		user_add(u);
		return 1;
	}
}



/*!
 * used to tell if two user structure are equal
 * @param u1 the fist user
 * @param u2 the second user
 * @see user_exist()
 * @return  1 if they are the same 0 otherwise
 * \version 1
 * \date   Feb  2007
 * \author Elie	
	Sort the test : fastest test first for optimisation	
 */

_u32 user_is_equal(t_user *u1, t_user *u2)
{	
	assert(u1 != NULL);
	assert(u2 != NULL);
	assert(u1->ip != 0);
	assert(u2->ip != 0);
	assert(u1->crc != 0);
	assert(u2->crc != 0);
	
	     if (u1->ip != u2->ip) return 0;
	else if (u1->crc != u2->crc) return 0;
	else if (strcmp(u1->login, u2->login) != 0) return 0;
	else if (strcmp(u1->pass,  u2->pass) != 0) return 0;
	else if (strcmp(u1->algorithm,  u2->algorithm) != 0) return 0;
	else if (strcmp(u1->additionnal,  u2->additionnal) != 0) return 0;
	else if (strcmp(u1->origin,  u2->origin) != 0) return 0;
	else return 1;
}


/*!
 * used to initialize the user hash table
 * @param o1 the fist soft
 * @param o2 the second soft 
 * @see main()
 * @return  the hash table
 * \version 1
 * \date   jan  2007
 * \author Elie
 */

t_hash *user_init(void)
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
		free(o); 
		warning("user hash initialize failed\n");
		return NULL; 
	} 
		
	bzero(o->table, size * sizeof(t_hash_entry *));
	o->tablelength  = size;
	o->primeindex   = pindex;
	o->type		= HASH_USER;
	o->entrycount   = 0;
	return o;
}

/*!
 * used to check if a user is already present into the hasttable
 * @param u the user to test
 * @see analyze_user()
 * @return  a pointer to the user if it exists NULL otherwise
 * \version 1
 * \date   Feb  2007
 * \author Elie	

 */

t_user *user_exist(t_user *u)
{
	_u32 		k, indexe;
	t_hash_entry 	*e;
	
	assert(users);
	assert(u);
	assert(u->crc);
	assert(users->table);
	
	k = u->crc;
	indexe = hash_indexFor(users->tablelength, k);
	assert(indexe);
	e = users->table[indexe];
	while (NULL != e)
	{
		if (user_is_equal(u,e->u)) 
			return e->u;
		e = e->next;
	}
	return NULL;
}


/*!
 * add a user to the hasttable
 * @param u the user to add
 * @see analyze_user()
 * @return  add_hash() value
 * \version 1
 * \date   Feb  2007
 * \author Elie
 */
int user_add(t_user *u)
{

	t_hash_entry	*h;
	_u32		 k;
	
	assert(u);
	assert(u->crc);
	//assigning uniq id

	bench.user_id++;
	u->id = bench.user_id;
	if (option.debug == 12)
		printf("USER id %lld added %s (%d/%d) coll %d\n",u->id, u->login, users->entrycount, users->tablelength, users->collision);
	h = (t_hash_entry *)malloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = u->crc;
	//adding key to hash entry for table resize
	h->k = k;
	//clipping user to hash entry
	h->u =	u;
	//clipping entry to hash table
	pthread_mutex_lock(&mutex.hashuser);
	add_hash(users, k, h);
	pthread_mutex_unlock(&mutex.hashuser);
	return 1;

}


/*!
 * Free a user structure
 * @param u the user to free
 * @return  Null
 * \version 1
 * \date   Feb  2007
 * \author Elie
 */
t_user *user_free(t_user *u)
{

	free(u);
	u = NULL;
	return NULL;
}
/*!
 * update user  structure
 * @param u the structure to update
 * @param new the new information
 * @see analyze_user()
 * @return  user structure
 * \version 1
 * \date   Feb  2007
 * \author Elie
 */
t_user *user_update(t_user *u, t_user *new)
{	
	u->frequency++;
	u->last_time = new->last_time;
	u->last_time_usec = new->last_time_usec;
	user_free(new);
	return NULL;
}


//Sort the hash table for displaying and stating
void user_sorting()
{

	_s32		i,j;
	t_hash_entry 	*e;
	analyze.user_stated = users->entrycount;
	if (users_list)
		free(users_list);
	users_list = (t_user **)malloc(sizeof(t_user*) * analyze.user_stated);
	bzero(users_list, sizeof(t_user*) * analyze.user_stated);
	for(j = 0, i = users->tablelength; i--;)
	{
		e = users->table[i];
		while (NULL != e)
		{
			users_list[j] = e->u;
			e = e->next;
			j++;
			//be aware of multithread .. host may have been added during the function
			if (j == analyze.user_stated)
				return;
		}
	}


}


void user_clean()
{
	_u32		i;
	_u32		t;
	t = time(NULL);
	t_hash_entry 	*e, *tmp;
 	t_hash_entry 	**pE;

	for(i = users->tablelength; i--;)
	{
		pE = &(users->table[i]);
    		e = *pE;
		e = users->table[i];
		while (NULL != e)
		{
			if(e->u->last_time + option.intervall < t)
			{
				tmp = e;
				*pE = e->next;
				e = e->next;
				free(tmp->u);
				free(tmp);
				users->entrycount--;
			} else {
				pE = &(e->next);
        			e = e->next;
			}
		}
	}
}
