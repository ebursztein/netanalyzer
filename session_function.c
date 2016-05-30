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
 *	\file session_function.c
 *	\brief functions used to sessions tracking and displaying.
 *
 *	This file contains every functions related to sessions handeling. This is also where the 
 *	hosts_add and traffic inspection start.
 *	\author  Elie
 *	\version 1.1
 *	\date    September 2006
 *	\bug  check that the session TCP automata is correct
 *	\todo ttl and isn tracking and sessions tracking for icmp, arp and other
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
extern	t_hash		*sessions;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_mutex		mutex;
_u64		session_id;
t_session	**sessions_list;
//inner function
int 		session_add(t_session *s);
t_session 	*session_free(t_session *s);
t_session 	*session_from_pkt(t_pkt *p);
t_session 	*session_exist(t_session *s);
t_session 	*session_update(t_session *s, t_session *new, _u8 state);
_s32		session_analyze_tcp(t_pkt *p);
_s32		session_analyze_udp_icmp(t_pkt *p);
_s8 		session_check_ttl(t_session *s, t_session *new);


//main function entry
_s32 analyze_session(t_pkt *p)
{	
	int 	ret = -1;
	//do we are consistent 
	assert(p->payload_len == p->len - p->decoded_len || p->len == 0);	
	if(p->pkt_proto == ARP)
		;
	else if (p->pkt_proto == ICMP)
		ret = session_analyze_udp_icmp(p);
	else if (p->pkt_proto == IP) {
		;
	} else if (p->pkt_proto >= UDP && p->pkt_proto < TCP) {
		ret = session_analyze_udp_icmp(p);
	} else if (p->pkt_proto >= TCP) {
		ret = session_analyze_tcp(p);
	}
	///\todo fixeme ICMP ARP IP AND OTHER IP PROTO ,CDP etc
	return ret;
}



void	session_store_current_state_in_pkt(t_pkt *p, t_session *s)
{
	p->nb_pkt_out = s-> nb_pkt_out;
	p->nb_pkt_in = s-> nb_pkt_in;
	p->last_time = s-> last_time;
	p->last_time_usec = s->last_time_usec;
	p->last_time_out = s-> last_time_out;
	p->last_time_out_usec = s->last_time_out_usec;
	p->last_time_in = s->last_time_in;
	p->last_time_in_usec = s->last_time_in_usec;
}


_s32 session_analyze_udp_icmp(t_pkt *p)
{
	t_session	*s;
	t_session	*new;
	_u8		way;
	
	assert(p != NULL);
	assert(p->udp != NULL || p->icmp != NULL);
	///\todo add isn tracking and ttl tracking to sessions
	new = session_from_pkt(p);
	if (new == NULL)
		return -2;
	
	if ((s = session_exist(new)) != NULL)
	{
		if(p->ip->src == s->src)
			way = CLIENT_TO_SERV;
		else
			way = SERV_TO_CLIENT;
		
		p->s = s;
		//saving current variable state to avoid race condition in profile and traffic analysis
			session_store_current_state_in_pkt(p, s);
		if(s->src == new->src)
			session_update(s, new, s->state);
		else
			session_update(s, new, SESS_UDP_ESTA);
		//host no new conn
		///!\todo need a if for performance ?
		//analyze_host(p, CONTINUE);
		if(p->sanity)
			analyze_error_pkt(s, p, s->id, 0);
		return CONTINUE;

	} else {
		
		if (option.debug == 9)
			printf("Session: adding UDP session from pkt %lld\n", p->id);
		session_add(new);
		p->s = new;
		//host add connection
		///!\todo need a if for performance ?
		//analyze_host(p, NEWCONN);
// 		traffic_analyze(new, p);
		if(p->sanity)
			analyze_error_pkt(new, p, new->id, 0);
		return NEWCONN;
	}
	return -1;
}


_s32 session_analyze_tcp(t_pkt *p)
{
	t_session	*s;
	t_session	*new;
	_u8		way;///!<to indicate the direction
	
	assert(p != NULL);
	assert(p->tcp != NULL);
	///\todo add isn tracking and ttl tracking to sessions
	new = session_from_pkt(p);
	if (new == NULL)
		return -2;
	if((p->tcp->flags & TCP_SYN) && !(p->tcp->flags & TCP_ACK))
	{
		if (option.debug == 9)
			printf("Session: adding TCP session from pkt %lld\n", p->id);
		session_add(new);
		p->s = new;
		//host add connection fixme test case
		//analyze_host(p, NEWCONN);
		if(p->sanity)
			analyze_error_pkt(new, p, new->id, 0);
		return NEWCONN;
	} else {
	//response
		if ((s = session_exist(new)) != NULL)
		{
			p->s = s;
			
			if (option.debug == 9)
				printf("session found session %lld\n", s->id);
			
			//saving current variable state to avoid race condition in profile and traffic analysis
			session_store_current_state_in_pkt(p, s);

			//TCP STATE TRACKING

			//ACK 
			if((p->tcp->flags & TCP_ACK) && (s->state == SESS_SYNACK)) {
				session_update(s, new, SESS_ACK);
			//Session is already on going
			} else if((p->tcp->flags & TCP_ACK) && (s->state == SESS_ACK)) {
				session_update(s, new, SESS_ACK);
			} else if((p->tcp->flags & TCP_SYN) && (p->tcp->flags & TCP_ACK)) {
				session_update(s, new, SESS_SYNACK);	//SYN ACK
			} else if((p->tcp->flags & TCP_RST) && (s->state == SESS_ACK)) {
				session_update(s, new, SESS_RST); 	//RST ESTH
			} else if((p->tcp->flags & TCP_RST) && (s->state == SESS_SYNACK)) {
				session_update(s, new, SESS_HALF_OPEN);	//HALF OPENE			
			} else if((p->tcp->flags & TCP_FIN) && (s->state == SESS_ACK)) {
				session_update(s, new, SESS_FIN);	//FIN ESTH
			} else if((p->tcp->flags & TCP_FIN) && (s->state == SESS_FIN) ) {
				session_update(s, new, SESS_FIN2);
			//NAUGHTY THINGS
			} else 	 if(((p->tcp->flags & TCP_FIN) && (s->state == SESS_FIN2)) || 	((p->tcp->flags & TCP_FIN) && (s->state == SESS_RST)) || ((p->tcp->flags & TCP_RST) && (s->state == SESS_RST)) || ((p->tcp->flags & TCP_RST) && (s->state == SESS_FIN2)))  {
				session_update(s, new, SESS_OVERCLOSE);
			} else if((p->tcp->flags & TCP_ACK) && !(p->tcp->flags & TCP_SYN) && (s->state == SESS_SYN)) {
				session_update(s, new, SESS_BLINDSPOOF);
			} else {
				session_update(s, new, SESS_PARTIAL_TCP);
			}
			//host no new conn
			//analyze_host(p, CONTINUE);
			if(p->ip->src == s->src)
				way = CLIENT_TO_SERV;
			else
				way = SERV_TO_CLIENT;
			if(p->sanity)
				analyze_error_pkt(s, p, s->id, 0);
			return CONTINUE;
		} else {
			if (option.debug == 9)
				printf("session can't find session for syn ack pkt\n");
			//partial (missed syn ?)
			new->state = SESS_PARTIAL_TCP;
			session_add(new);
			p->s = new;
			//host add connection
			//analyze_host(p, NEWCONN);
			if(p->sanity)
				analyze_error_pkt(new, p, new->id, 0);
			return CONTINUE;
		}
		
	}

	return -1;
}


static _u32 session_key(_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto)
{
	//_u8 i;
	//char str[14];
	_u32 key;
	_u32 k1, k2;
	//_u32 key =   3267000013; //7545
	//bzero(str, 14);
	//sprintf(str,"%4x%4x%2x%2x%2x",s->src, s->dst, s->sport, s->dport, s->proto);
	
	//dan bernstein djb2
	/*for(i = 12; i; i--)
	key = ((key << 5) + key) + str[i]; // hash * 33 + c 
	*/
	/*
	worst
	for(i = 12; i; i--)
	key = str[i] + (key << 3) + (key << 7) - key;
	return key;
	*/
	
	//persnoal try
	//							num of collision
	//return (s->dst ^ s->src) & (s->sport ^ s->dport ); //25611
	//return (s->dst | s->src) ^ (s->sport & s->dport ); //24435 
	//return (s->dst & s->src) | (s->sport ^ s->dport ) + s->proto; //13366
	//return ((dst / sport) * (src / dport ) + proto); //8562
	//return (s->dst & s->src) ^ (s->sport ^ s->dport ); //8255
	//return (s->dst & s->src) * (s->sport ^ s->dport ); //7623
	//return (dst & src) * (sport ^ dport ) - proto; //7612
	
	
	//Big endian / littel endian youhou
	//trying to remove address mask
	k1 = (src >> 16);
	k1 +=  (dport * sport) * proto;
	k2 = (dst >> 16);
	k2 += (dport +  sport) * proto;
	key = (k1 +k2);
	if (option.debug == 9)
		printf("session key : %u %u %u\n", k1, k2, key);
	//key -= (dst & src) * (sport ^ dport ) - proto;//7492 41
	//key *= (dst & src) * (sport ^ dport ) - proto;//7559
	
	//add java hashtable core shiffting
	/*key += ~(key << 9);
	key ^=  ((key >> 14) | (key << 18)); // >>>
	key +=  (key << 4);
	key ^=  ((key >> 10) | (key << 22)); // >>> 
	return key; //7568 \o/ very usefull */
	
	//others shifting 
	//key = key ^ (key >> 15); //7473
	//key = key ^ (key >> 16); //7563
	/*
	key = key ^ (key << 11);
	key = key ^ (key >> 11); //7583
	*/
	
	//key = key ^ (key >> 13);
	//key = key ^ (key >> 5);
	return key;
	
}

/*!
 * compare two session and say if they are the same
 * @param s1 first session
 * @param s2 second session
 * @return 1 if equal 0 otherwise
 * @see session_exist()
 * \version 1.0
 * \date   Sept 2006
 * \author Elie
 * \attention
 * \todo
 */
_u32 session_is_equal(t_session *s1, t_session *s2)
{
	///!\todo handle time out properly
	assert(s1);
	assert(s2);
	
	if(s1->nature == SESS_IS_UNICAST && s2->start_time - s1->last_time >  option.session_timeout )		return 0;
	if(s1->nature == SESS_IS_BROADCAST && s2->start_time  - s1->last_time > option.broadcast_timeout) 	return 0;
	if (s2->proto != s1->proto) 										return 0;
	if (!((s1->src == s2->src && s1->dst == s2->dst && s1->sport == s2->sport &&  s1->dport == s2->dport)
	|| (s1->src == s2->dst && s1->dst == s2->src && s1->sport == s2->dport &&  s1->dport == s2->sport))) 	return 0;
	return 1;				
}

/*!
 * session hash table initialisation function 
 * @return a pointer to a hash strucutre if ok NULL othewise
 * \version 1
 * \date    Jun 2006
 * \author Elie
 * \see setup_default()
 * \attention
 * \todo
 */
t_hash *session_init(void)
{
	t_hash *h;
	_u8 pindex = 0;
	_u32 size = primes[pindex];
	//init the session counter to 0
	session_id = 0;
	h = (t_hash *)malloc(sizeof(t_hash));
	if (h == NULL) 
		return NULL; /*oom*/
	// ** for table of pointer
	h->table = (t_hash_entry **)malloc(sizeof(t_hash_entry) * size);
	if (NULL == h->table) { 
		free(h); 
		warning("hash table aallocation failed\n");
		return NULL; } /*oom*/
		
	bzero(h->table, size * sizeof(t_hash_entry *));
	h->tablelength  = size;
	h->primeindex   = pindex;
	h->type		= HASH_SESSION;
	h->entrycount   = 0;
	return h;
}

/*!
 * used to update a session with the incoming packet
 * @param s the session
 * @param new the new packet in session format
 * @param state the updated state according to the protocol automate 
 * @see analyze_session()
 * @see session_analyze_tcp()
 * @see session_analyze_udp()
 * @return  the updated session
 * \version 1.1
 * \date    Sept 2006
 * \author Elie
 * \attention it free new! so dont use it any more bad bad behavior
 * \todo
 */
t_session *session_update(t_session *s, t_session *new, _u8 state)
{
	//check back in time : new->time < s->last_seen
	assert(new->last_time >= s->last_time);
	//ttl tracking
	session_check_ttl(s,new);
	//check pkt way
	if (s->src == new->src)
	{
		//regular client -> server mean pkt out
		s->nb_pkt_out++;
		s->bytes_out += new->bytes_out;
		s->last_time_out = new->last_time_out;
		s->last_time_out_usec = new->last_time_out_usec;
	} else {
		//GOOPHY
		s->nb_pkt_in++;
		s->bytes_in += new->bytes_out;
		s->last_time_in = new->last_time_out;
		s->last_time_in_usec = new->last_time_out_usec;
	}
	s->last_time = new->start_time;
	s->last_time_usec = new->start_time_usec;
	s->sanity = s->sanity | new->sanity;
	//state update
	s->state = state;
	free(new);
	return s;
}

/*!
 * used to detect ttl change.  and compute ttl distance
 * This denote either a route change or ids evasion or arp spooof
 * @param s the session
 * @param new the packet to check in session format
 * @see analyze_session()
 * @return 0 is ok -1 if not correct
 * \version 1.1
 * \date    Sept 2006
 * \author Elie
 * \attention
 * \todo
 */

_s8  session_check_ttl(t_session *s, t_session *new)
{
	//s->ttl_in	 ///!<ttl client
	assert(s->proto >= IP);
	if(s->src == new->src)
	{	
		//printf("ttl:%d/%d\n", s->ttl_in, new->ttl_in);
		if(s->ttl_out != new->ttl_out)
		{
			///\todo add ttl change detection in error reporting
			//printf("ttl out check failed%d:%d\n",p->ip->ttl, s->ttl_out );
			s->ttl_out = new->ttl_out;
			s->distance_out = traffic_ttl_distance(s->ttl_out, "", "");
			return -1;
		} 
	} else {
		if(!s->ttl_out)
		{
			s->ttl_in = new->ttl_out;
			s->distance_in = traffic_ttl_distance(s->ttl_in, "", "");
		}
		if(s->ttl_out != new->ttl_in)
		{
			//printf("session :%lld ttl in check failed%d:%d(%d) %u:%u\n",s->id, p->ip->ttl, s->ttl_in, s->ttl_out, s->src, s->dst );
			s->ttl_in = new->ttl_out;
			s->distance_in = traffic_ttl_distance(s->ttl_in, "", "");
			return -1;
		}
	}
	return 0;
}




t_session *session_exist(t_session *s)
{
	_u32 		k, indexe;
	t_hash_entry 	*e;
	//two possibility one choice :P
	//forward client->server
	k = session_key(s->src, s->dst, s->sport, s->dport, s->proto);
	indexe = hash_indexFor(sessions->tablelength, k);
	e = sessions->table[indexe];
	while (NULL != e)
	{
		if (session_is_equal(e->s, s)) 
			return e->s;
		e = e->next;
	}
	//backward server->client
	k = session_key(s->dst, s->src, s->dport, s->sport, s->proto);
	indexe = hash_indexFor(sessions->tablelength, k);
	e = sessions->table[indexe];
	while (NULL != e)
	{
		if (session_is_equal(e->s, s))
			return e->s;
		
		e = e->next;
	}
	return NULL;
}

/*!
 * used to convert a pkt structure into a session structure
 * @param p the packet to convert
 * @see analyze_session()
 * @see session_analyze_tcp()
 * @see session_analyze_udp
 * @return the session created according to the packet
 * \version 1.1
 * \date    Sept 2006
 * \author Elie
 * \attention
 * \todo ICMP ARP and other sessions type
 */
t_session *session_from_pkt(t_pkt *p)
{
	t_session	*s;
	//fixme udp icmp arp 
	//init session
	s = (t_session *)malloc(sizeof(t_session));
	bzero(s, sizeof(t_session));	
	
	if (p->pkt_proto >= TCP)
	{
		s->state 	= SESS_SYN;
		s->sport	= p->tcp->sport;
		s->dport	= p->tcp->dport;
	} else if (p->pkt_proto >= UDP) {
		s->state 	= SESS_UDP_OPEN;
		s->sport	= p->udp->sport;
		s->dport	= p->udp->dport;	
	}
	s->sanity		= p->sanity;
	s->proto		= p->pkt_proto;
	s->src			= p->ip->src;
	s->dst			= p->ip->dst;
	s->ttl_out		= p->ip->ttl; ///!<ttl client
	s->distance_out		= traffic_ttl_distance(s->ttl_out, "", "");
	s->start_time 		= p->time_capture;
	s->start_time_usec	= p->time_capture_usec;
	s->last_time		= p->time_capture;
	s->last_time_usec	= p->time_capture_usec;
	s->last_time_out 	= p->time_capture;
	s->last_time_out_usec 	= p->time_capture_usec;
	s->nb_pkt_out		= 1;
	s->bytes_out		= p->len;
	//session nature
	if (p->pkt_proto >= IP)
	{
		if (ip_is_broadcast(s->src) || ip_is_broadcast(s->dst))
			s->nature = SESS_IS_BROADCAST;
		else
			s->nature = SESS_IS_UNICAST;
	}
	return s;
}

//just freeing the entry
t_session *session_free(t_session *s)
{
	free(s);
	s = NULL;
	return NULL;
}
int session_add(t_session *s)
{
	t_hash_entry	*h;
	_u32		k;
	//New session is in control phase by default
	s->phase_client = CONTROL_PHASE;
	s->phase_server = CONTROL_PHASE;
	
	h = (t_hash_entry *)malloc(sizeof(t_hash_entry));
	bzero(h, sizeof(t_hash_entry));
	//giving unique id to a session
	session_id++;
	s->id = session_id;
	//compute hash key
	//_u32 src, _u32 dst, _u16 sport, _u16 dport, _u16 proto
	k = session_key(s->src, s->dst, s->sport, s->dport, s->proto);
	//adding key to hash entry for table resize
	h->k = k;
	//clipping session to hash entry
	h->s =	s;
	//clipping entry to hash table
	if(analyze.tcpdump)
		livedump_display_newsess(s);
	pthread_mutex_lock(&mutex.hashsession);
	add_hash(sessions, k, h);
	pthread_mutex_unlock(&mutex.hashsession);
	return 1;
}

//Sort the hash table for displaying and stating
void session_make_array()
{
	_s32		i,j;
	t_hash_entry 	*e;
	analyze.session_stated = sessions->entrycount;
	if (sessions_list)
		free(sessions_list);
	sessions_list = (t_session **)xmalloc(sizeof(t_session*) * analyze.session_stated);
	bzero(sessions_list, sizeof(t_session*) * analyze.session_stated);
	for(j = 0, i = sessions->tablelength; i--;)
	{
		e = sessions->table[i];
		while (NULL != e)
		{
			sessions_list[j] = e->s;
			e = e->next;
			j++;
			//warning multi thread -> session may have been hade during the function exec
			if (j == analyze.session_stated)
				return;
		}
	}

}

/*!
 * used to timeout session, remove timeouted and clear counter
 * \version 1.2
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo add clear counter
 */
void session_clean()
{
	_u32			i;
	_u32			t;
	t_protocol_info		*p, *ptmp;
	t_file			*f, *ftmp;
	t_hash_entry 		*e, *tmp;
 	t_hash_entry 	**pE;

	
	t = time(NULL);
	for(i = sessions->tablelength; i--;)
	{
		pE = &(sessions->table[i]);
    		e = *pE;
		while (NULL != e)
		{
			//timed out
			//if((t - e->s->last_time > option.session_timeout && e->s->nature != SESS_IS_BROADCAST) || (t - e->s->last_time > option.broadcast_timeout && e->s->nature == SESS_IS_BROADCAST))
			if(t - e->s->last_time > option.session_timeout)
			{
				//printf("I want to shoot session %lld",e->s->id);
				tmp = e;
				*pE = e->next;
				e = e->next;
				session_free(tmp->s);
				free(tmp);
				sessions->entrycount--;
				continue;
			} else {
			//	printf("Not yet:%lld time:%d last:%lld diff:%lld\n", e->s->id, t, e->s->last_time, (t - e->s->last_time));
				e->s->nb_pkt_in	 	= 0;
				e->s->nb_pkt_out 	= 0;
				e->s->bytes_in 	 	= 0;
				e->s->bytes_out	 	= 0;
				e->s->file_client 	= 0;
				e->s->file_server 	= 0;
				//file and protocol need to  be cleaned because they are not used otherwise 
				//Other must NOT be freed they are handled by their own structure
				p = e->s->protocol;
				while(p)
				{
					ptmp = p;
					p = p->next;
					free(ptmp);
				}
				f = e->s->file;
				while(f)
				{
					ftmp = f;
					f = f->next;
					free(ftmp);
				}		
				///\todo clean guessing list s->proto_candidat		
				e->s->protocol 		= NULL;
				e->s->last_protocol	= NULL;
				e->s->client		= NULL;
				e->s->last_client	= NULL;
				e->s->server		= NULL;
				e->s->last_server	= NULL;
				e->s->file		= NULL;
				e->s->last_file		= NULL;
				e->s->user		= NULL;
				e->s->last_user		= NULL;
				e->s->user2user		= NULL;
				e->s->last_user2user	= NULL;
				pE = &(e->next);
				e = e->next;
			}
		}
	}
}

