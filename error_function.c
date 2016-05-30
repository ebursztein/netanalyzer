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
 *	\file error_function.c
 *	\brief functions used for errors tracking and displaying.
 *
 *	This file contains every functions related errors handeling. This is also where the 
 *	classification file is used
 *	\author  Elie
 *	\version 1.0
 *	\date    Febuary 2007
 *	\bug  
 *	\todo 
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
#include "headers/pattern_inspection.h"


extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*errors;
extern	t_benchmark	bench;
extern	t_analyze	analyze;
extern 	t_option	option;
extern	t_mutex		mutex;
t_error		**errors_list;


t_error *error_exist(_u64 hash, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target, _s64 last_time, _s64 last_time_usec);
t_error *error_update(t_error *e, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target,  _s64 last_time, _s64 last_time_usec);
t_error *error_add(_u64 hash, t_pkt *p, _u64 s, _u64 hid, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target,  _s64 last_time, _s64 last_time_usec);

/*!
 * entry point to report an error 
 * Add classification details and store information in the hash table
 * @param sess session involved (used for livedump)
 * @param p packet involved
 * @param s the session id involved
 * @param h the host id involved
 * @param ip the ip used
 * @param type type of error : event or error
 * @param layer TCP/IP layer where it comme from
 * @param class classification shortname
 * @param name event name
 * @param group of the event : error login, leak etc
 * @param details detailss about the event
 * @param target target of the event user, file, protocol etc
 * @param last_time time of the error in sec
 * @param last_time_usec time of the error in usec
 * @return 0 is ok -1 if not correct
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
int analyze_error(t_session *sess, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target, _s64 last_time, _s64 last_time_usec)
{
	t_error 	*e;
	_u64		hash = 0;
	
	//assert
	assert(name 	!= NULL);
	assert(group 	!= NULL);
	assert(layer	> 0);
	assert(type == TYPE_ERROR || type == TYPE_EVENT);
	
	if (option.debug == 26)
		printf("Adding error/event layer:%d type:%d %s:%s\n",layer, type, name, group);
	//hash
	hash += crc(class);
	hash += crc(name);
	hash += crc(group);
	hash += crc(details);
	hash += crc(target);
	hash += ip;
	e = error_exist(hash, p, s, h, ip, type, layer, class, name, group, details, target, last_time, last_time_usec);
	if(e != NULL)
		e = error_update(e, p, s, h, ip, type, layer, class, name, group, details, target, last_time, last_time_usec);
	else
		e = error_add(hash, p, s, h, ip, type, layer, class, name, group, details, target, last_time, last_time_usec);
	
	if(analyze.tcpdump)
		livedump_display_error(e, p, sess);
	
	return 1;
}

/*!
 * Insert packet error into errors hashtable 
 * @param sess session involved (used for livedump)
 * @param p packet involved
 * @param s the session id involved
 * @param h the host id involved
 * @return 0 is ok -1 if not correct
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
int analyze_error_pkt(t_session *sess, t_pkt *p, _u64 s, _u64 h)
{
	_u32	ip = 0;
	_s64	last_time;
	_s64	last_time_usec;
	_u8 	type = TYPE_ERROR;
	
	last_time = p->time_capture;
	last_time_usec = p->time_capture_usec;
	
	if (p->ip)
		ip = p->ip->src;
	
	//class, name, group, details, target
	if (p->sanity & SANITY_ARP_TRUNK) 
		analyze_error(sess, p, s, h, ip, type, 1, "packet-error", "Trunked", "error", "Collision or Invalid arp packet", "Network", last_time, last_time_usec);
	if (p->sanity & SANITY_IP_TRUNK)
		analyze_error(sess, p, s, h, ip, type, 2, "packet-error", "Trunked", "error", "IP packet too short", "Network", last_time, last_time_usec);
	if (p->sanity & SANITY_TCP_TRUNK)
		analyze_error(sess, p, s, h, ip, type, 3, "packet-error", "Trunked", "error", "TCP packet too short", "Network", last_time, last_time_usec);
	if (p->sanity & SANITY_UDP_TRUNK)
		analyze_error(sess, p, s, h, ip, type, 3, "packet-error", "Trunked", "error", "UDP packet too short", "Network", last_time, last_time_usec);
	if (p->sanity & SANITY_ICMP_TRUNK)
		analyze_error(sess, p, s, h, ip, type, 2, "packet-error", "Trunked", "error", "ICMP packet too short", "Network", last_time, last_time_usec);
	if (p->sanity & SANITY_TCP_LEAK)
		analyze_error(sess, p, s, h, ip, type, 3, "leak", "Leak", "leak", "Urgent point not empty along with no Flag URG", "Host", last_time, last_time_usec);
	if (p->sanity & SANITY_IP_LEAK)
		analyze_error(sess, p, s, h, ip, type, 2, "leak", "Leak", "leak", "Frag offset not empty along with no fragmentation", "Host", last_time, last_time_usec);
	if (p->sanity & SANITY_TCP_FINGER)
		analyze_error(sess, p, s, h, ip, type, 3, "recon-fingerprint", "Fingerprint", "recon", "TCP Fingerprint packet (NMap test)", "Host", last_time, last_time_usec);
	if (p->sanity & SANITY_ICMP_FINGER)
		analyze_error(sess, p, s, h, ip, type, 3, "recon-fingerprint", "Fingerprint", "recon", "ICMP Fingerprint packet (Xprobe test)", "Host", last_time, last_time_usec);

	return 0;
}

		
/*!
 * say if two error are equals 
 * @param error error to compare with
 * @param p packet involved
 * @param s the session id involved
 * @param h the host id involved
 * @param ip the ip used
 * @param type type of error : event or error
 * @param layer TCP/IP layer where it comme from
 * @param class classification shortname
 * @param name event name
 * @param group of the event : error login, leak etc
 * @param details detailss about the event
 * @param target target of the event user, file, protocol etc
 * @param last_time time of the error in sec
 * @param last_time_usec time of the error in usec
 * @see error_exist
 * @return 1 if equal 0 otherwise
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
int error_is_equal(t_error *e, _u64 hash, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target, _s64 last_time, _s64 last_time_usec)
{
	//numeric first for speed reason
	if (e->crc != hash)	return 0;
	if (e->ip != ip) 	return 0;
	if (e->layer != layer) 	return 0;
	if (e->type != type) 	return 0;
	//get more slow	
	if(strncmp(e->name, name, sizeof(e->name)) != 0) return 0;
	if(strncmp(e->group, group, sizeof(e->group)) != 0) return 0;
	//we do not need to test the two above i guess
	//if(strncmp(e->details, details, sizeof(e->details)) != 0) return 0;
	//if(strncmp(e->target, target, sizeof(e->target)) != 0) return 0;
	return 1;
}

/*!
 * Is the error already present in the hash ? 
 * @param hash crc value for faster comparaison
 * @param s the session involved
 * @param h the host involved
 * @param ip the ip used
 * @param type type of error : event or error
 * @param layer TCP/IP layer where it comme from
 * @param class classification shortname
 * @param name event name
 * @param group of the event : error login, leak etc
 * @param details detailss about the event
 * @param target target of the event user, file, protocol etc
 * @param last_time time of the error in sec
 * @param last_time_usec time of the error in usec
 * @return the error if found NULL otherwise
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
t_error *error_exist(_u64 hash, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target, _s64 last_time, _s64 last_time_usec)
{
	_u32 		index;
	t_hash_entry 	*e;
	index = hash_indexFor(errors->tablelength,hash);
	e = errors->table[index];
	while (NULL != e)
	{
		if (error_is_equal(e->e, hash, p, s, h, ip, type, layer, class, name, group, details, target, last_time, last_time_usec))
			return e->e;
		e = e->next;
	}
	return NULL;
}
/*!
 * update an error if already present in database 
 * @param e the error to update
 * @param s the session involved
 * @param h the host involved
 * @param ip the ip used
 * @param type type of error : event or error
 * @param layer TCP/IP layer where it comme from
 * @param class classification shortname
 * @param name event name
 * @param group of the event : error login, leak etc
 * @param details detailss about the event
 * @param target target of the event user, file, protocol etc
 * @param last_time time of the error in sec
 * @param last_time_usec time of the error in usec
 * @return the error if okay NULL otherwise
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
 
t_error *error_update(t_error *e, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target,  _s64 last_time, _s64 last_time_usec)
{
	e->last_time = last_time;
	e->last_time_usec = last_time_usec;
	e->frequency++;
	return e;
}


/*!
 * fill classification details to an error according to it shortname
 * Add classification details to an error
 * @param e the error to report
 * @param class the classification shortname
 * \version 1.1
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo add classification hash
 */
void	error_add_classification(t_error *e, char *class)
{
	if(!class)
		return;
	//class
	if(class) strncpy(e->class_shortname, class, sizeof(e->class_shortname));
	//need to perform a class lookup here
}
/*!
 * Add a session to the hash table
 * @param e the error to add 
 * @param s the session id involved
 * @param h the host id involved
 * @param ip the ip used
 * @param type type of error : event or error
 * @param layer TCP/IP layer where it comme from
 * @param class classification shortname
 * @param name event name
 * @param group of the event : error login, leak etc
 * @param details detailss about the event
 * @param target target of the event user, file, protocol etc
 * @return the added error
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo
 */

t_error *error_add(_u64 hash, t_pkt *p, _u64 s, _u64 hid, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target,  _s64 last_time, _s64 last_time_usec)
{
	t_hash_entry	*h;
	_u32		 k;
	t_error		 *e;

	e = (t_error *)xmalloc(sizeof(t_error));
	bzero(e, sizeof(t_error));
	
	///!\todo increment error /request and reply in session
	
	e->crc = hash;
	e->type = type;
	e->layer = layer;
	
	if(name) strncpy(e->name, name, sizeof(e->name));
	if(group) strncpy(e->group, group, sizeof(e->group));
	if(details) strncpy(e->details, details, sizeof(e->details));
	if(target) strncpy(e->target, target, sizeof(e->target));
	bench.error_id++;
	
	//id
	e->id = bench.error_id;
	e->session_id = s;
	e->host_id = hid;
	e->ip = ip;
	
	
	//temporal
	e->frequency = 1;
	e->first_time = last_time;
	e->last_time = last_time;
	e->first_time_usec = last_time_usec;
	e->last_time_usec = last_time_usec;
	
	
	//class
	error_add_classification(e, class);

	
	if (option.debug == 13)
		printf("Error id %lld added layer:%d type:%d (%d/%d) coll %d\n",e->id, e->layer, e->type, errors->entrycount, errors->tablelength, errors->collision);
	
	h = (t_hash_entry *)xmalloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = hash;
	//adding key to hash entry for table resize
	h->k = k;
	//clipping error to hash entry
	h->e =	e;
	//clipping entry to hash table
	pthread_mutex_lock(&mutex.hasherror);
	add_hash(errors, k, h);
	pthread_mutex_unlock(&mutex.hasherror);
	return e;
	
}
/*!
 * error hash table initialisation function 
 * @return a pointer to a hash strucutre if ok NULL othewise
 * \version 1
 * \date    Feb 2007
 * \author Elie
 * \see setup_default()
 * \attention
 * \todo
 */

t_hash *error_init(void)
{
	t_hash *h;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	//init the session counter to 0
	bench.error_id = 0;
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
		h->type		= HASH_ERROR;
		h->entrycount   = 0;
		return h;
}





//Sort the hash table for displaying and stating
void error_sorting()
{
	_u32		i,j;
	t_hash_entry 	*e;
	analyze.error_stated = errors->entrycount;
	if (errors_list)
		free(errors_list);
	errors_list = (t_error **)malloc(sizeof(t_error*) * analyze.error_stated);
	bzero(errors_list, sizeof(t_error*) * analyze.error_stated);
	for(j = 0, i = errors->tablelength; i--;)
	{
		e = errors->table[i];
		while (NULL != e)
		{
			errors_list[j] = e->e;
			e = e->next;
			j++;
			//warning multi thread -> session may have been hade during the function exec
			if (j == analyze.error_stated)
				return;
		}
	}

}


void error_clean()
{
	_u32		i;
	_u32		t;
	t = time(NULL);
	t_hash_entry 	*e, *tmp;
 	t_hash_entry 	**pE;

	for(i = errors->tablelength; i--;)
	{
		pE = &(errors->table[i]);
    		e = *pE;
		while (NULL != e)
		{
			if(e->e->last_time + option.intervall < t)
			{
				tmp = e;
				*pE = e->next;
				e = e->next;
				free(tmp->e);
				free(tmp);
				errors->entrycount--;
			} else {
				///!\todo fixe me cleanup
				e->e->frequency = 0;
				pE = &(e->next);
        			e = e->next;
			}
		}
	}
}
