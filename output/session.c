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
 * \file session.c
 * \brief functions used for sessions ouput in the output thread
 * \author  Elie
 * \version 1.1
 * \date    Aug 2007
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
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"

extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*sessions;
extern	t_option	option;
extern	t_analyze	analyze;
extern 	t_session	**sessions_list;
extern	t_tuning	tuning;

//sorting prototype
int cmp_session_traf(const void *a, const void *b);
int cmp_session_time(const void *a, const void *b);
int cmp_session_proto(const void *a, const void *b);

void session_display_plain(t_session *s);
void session_display_xml(t_session *s);

void session_display_guest_plain(t_session *s);
void session_display_guest_xml(t_session *s);

void session_display_state_plain(t_session *s);

void session_display_protocol_plain(t_session *s);
void session_display_protocol_xml(t_session *s);

void session_display_file_plain(t_session *s);
void session_display_file_xml(t_session *s);

void session_display_user_plain(t_session *s);
void session_display_user_xml(t_session *s);

/*!
 * output session
 * @param type of the output (not in use)
 * @param limit number of sessions to display
 * @see output()
 * \version 1.2
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo use type to select sorting
 */ 
void session_output(_u8 type, _s32 limit)
{
	_u32 		 i, max;
	t_session	*s;

	limit = type;
	//sort by start time
	//qsort(sessions_list, analyze.session_stated, sizeof(t_session*), cmp_session_start);
	//"smart sort"
	qsort(sessions_list, analyze.session_stated, sizeof(t_session*), cmp_session_traf);
	if (option.xml)
		out("<flows>");
	else
		out("###Flows report###\n");
	//limiting output if requested
	if (analyze.session > 0 && analyze.session < analyze.session_stated)
		max = analyze.session;
	else
		max = analyze.session_stated;
	//can't do it backward due to sorting
	for(i = 0; i < max; i++)
	{
		if ((s = sessions_list[i]) != NULL)
		{
			if(s->bytes_in + s->bytes_out != 0)
			{	
				if(option.xml)
					session_display_xml(s);
				else
					session_display_plain(s);
			}
		}
	}
	if(option.xml)
		out("</flows>");
}


/*!
 *  display a single session in xml
 * @param s the session to display
 * @see session_output()
 * \version 1.0
 * \date    Mar 2007
 * \author Elie
 * \attention
 */ 
void session_display_xml(t_session *s)
{
	out("\t<flow k=\"%d\"  id=\"%lld\"  client_id=\"%d\" server_id=\"%d\" state=\"%d\"  nature=\"%d\"  sanity=\"%d\"  proto=\"%d\"  src=\"%d\"  dst=\"%d\"  sport=\"%d\"  dport=\"%d\"  start_time=\"%lld\"  start_time_usec=\"%lld\"  last_time=\"%lld\"  last_time_usec=\"%lld\"  last_time_in=\"%lld\"  last_time_in_usec=\"%lld\"  last_time_out=\"%lld\"  last_time_out_usec=\"%lld\"  nb_pkt_in=\"%d\"  nb_pkt_out=\"%d\"  bytes_in=\"%d\"  bytes_out=\"%d\"  default_ttl_in=\"%d\"  default_ttl_out=\"%d\"  ttl_in=\"%d\"  ttl_out=\"%d\"  distance_in=\"%d\"  distance_out=\"%d\"  file_client=\"%d\"  file_server=\"%d\"  file_client_len=\"%d\"  file_server_len=\"%d\"  file_client_pkt_num=\"%d\"  file_server_pkt_num=\"%d\"  req_client=\"%d\"  req_server=\"%d\"  rep_client=\"%d\"  rep_server=\"%d\"  err_client=\"%d\"  err_server=\"%d\"  guest_protocol=\"%s\"  protocol_probability=\"%d\"   phase_client=\"%d\"  phase_server=\"%d\"  last_size_client=\"%d\"  last_size_server=\"%d\"  file_client_last_len=\"%d\"  file_server_last_len=\"%d\"  file_client_last_pkt_num=\"%d\"  file_server_last_pkt_num=\"%d\"> \n",
	s->k, s->id, s->client_id, s->server_id, s->state, s->nature, s->sanity, s->proto, s->src, s->dst, s->sport, s->dport, s->start_time, s->start_time_usec, s->last_time, s->last_time_usec, s->last_time_in, s->last_time_in_usec, s->last_time_out, s->last_time_out_usec, s->nb_pkt_in, s->nb_pkt_out, s->bytes_in, s->bytes_out, s->default_ttl_in, s->default_ttl_out, s->ttl_in, s->ttl_out, s->distance_in, s->distance_out, s->file_client, s->file_server, s->file_client_len, s->file_server_len, s->file_client_pkt_num, s->file_server_pkt_num, s->req_client, s->req_server, s->rep_client, s->rep_server, s->err_client, s->err_server, s->guessed_protocol->name, s->guess_probability, s->phase_client, s->phase_server, s->last_size_client, s->last_size_server, s->file_client_last_len, s->file_server_last_len, s->file_client_last_pkt_num, s->file_server_last_pkt_num);
	
	session_display_protocol_xml(s);
	session_display_file_xml(s);
	user_session_display_xml(s);
	user2user_session_display_xml(s);
	software_session_display_xml(s);
	
	///other protocol probabity if needed
	if(s->guess_probability != 0 && s->guess_probability != 100) 
		session_display_guest_xml(s);
	out("\t</flow>\n");

}

/*!
 *  display a single session
 * @param s the session to display
 * @see session_output()
 * \version 1.2
 * \date    Feb 2007
 * \author Elie
 * \attention
 * \todo fixeme ARP
 */ 

void session_display_plain(t_session *s)
{
	struct 	in_addr		src;
	struct 	in_addr		dst;
	char 			traf_in[BUFF_S];
	char			traf_out[BUFF_S];
	
	if(s->proto >= IP)
	{
		src.s_addr = s->src;
		dst.s_addr = s->dst;
	}
	if (s->proto == ARP)
	;
	
	///#### LINE 1 : traf stat
	//protocol
	out("%s%s%s (",cl.yel, s->guessed_protocol->name, cl.clr);
	
	//fancy for proba
	     if (s->guess_probability >= 75) 	out("%s", cl.gre);
	else if (s->guess_probability >= 50) 	out("%s", cl.yel);
	else 					out("%s", cl.red);
	
	//protocol probability
	out("%d%s\%):",s->guess_probability, cl.clr);
	
	//client
	out("%15s:%s%5d%s",inet_ntoa(src), cl.pur, ntohs(s->sport), cl.clr);
	
	if (s->state == SESS_PARTIAL_TCP)
		out(" %s<?>%s ", cl.red, cl.clr);
	else
		out(" %s->%s ", cl.yel, cl.clr);
	//server
	out("%15s:%s%5d%s", inet_ntoa(dst), cl.pur, ntohs(s->dport), cl.clr);

	//general transfert information
	out("\tfiles %s%d%s/%s%d%s Req:%s%d%s/%s%d%s Rep:%s%d%s/%s%d%s Err:%s%d%s/%s%d%s", cl.gre, s->file_client, cl.clr,  cl.cya, s->file_server, cl.clr, cl.gre, s->req_client, cl.clr, cl.cya, s->req_server, cl.clr, cl.gre, s->rep_client, cl.clr, cl.cya, s->rep_server, cl.clr, cl.cya, s->err_client, cl.clr, cl.cya, s->err_server, cl.clr);
	
	//session state
	out(" %s", cl.yel);
	session_display_state_plain(s);
	out("%s\n", cl.clr);
	
	///#### LINE 2 : traf stat
	output_trafic(s->bytes_in, traf_in);
	output_trafic(s->bytes_out, traf_out);
	out("[Traffic]   C:%s%s/s%s (%s%dpkt%s) S:%s%s/s%s (%s%d%spkt)",cl.gre,traf_out, cl.clr, cl.cya, s->nb_pkt_out, cl.clr, cl.cya,traf_in, cl.clr, cl.pur, s->nb_pkt_in, cl.clr);
	//distance
	if (s->distance_out > 0)
		out(" [Distance] C:%s%d%s", cl.gre, s->distance_out, cl.clr);
	else 
		out(" [Distance] C:%slocal%s", cl.gre, cl.clr);
	
	if (s->distance_in > 0)
		out(" S:%s%d%s", cl.cya, s->distance_in, cl.clr);
	else 
		out(" S:%slocal%s", cl.cya, cl.clr);
	out("\n");	
	
	if (option.quiet)
		return;
	///#### pattern
	session_display_protocol_plain(s);
	session_display_file_plain(s);
	user_session_display_plain(s);
	user2user_session_display_plain(s);
	software_session_display_plain(s);
	
	///other protocol probabity if needed
	if(s->guess_probability != 0 && s->guess_probability < tuning.proba_display) {
		session_display_guest_plain(s);
	}
	///#### Spearator
	out("\n");
}


void session_display_guest_plain(t_session *s) {
	t_session_protocol 	*proto;
	
	proto = s->proto_candidat;
	//init
	while(proto != NULL && (int)proto->proba_porthint + (int)proto->proba_profile + (int)proto->proba_pattern > 0)
	{	
		out("[Guess protocol] %s:%d\% Port:%d\% Prof:%d\% Patt:%d\%\n", proto->name, proto->proba, (int)proto->proba_porthint, (int)proto->proba_profile, (int)proto->proba_pattern);
		proto = proto->next;
	}
}

void session_display_guest_xml(t_session *s) {
	t_session_protocol 	*proto;
	
	proto = s->proto_candidat;
	//init
	while(proto != NULL && (int)proto->proba_porthint + (int)proto->proba_profile + (int)proto->proba_pattern > 0)
	{	
		out("<guest proba=\"%d\" port=\"%d\" profile=\"%d\"  pattern=\"%d\">", proto->proba, (int)proto->proba_porthint, (int)proto->proba_profile, (int)proto->proba_pattern);
		out("%s</guest>\n", proto->name);
		proto = proto->next;
	}	
}



/*!
 *  display session state
 * @param s the session to display
 * @see session_display_plain()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 */ 
void session_display_state_plain(t_session *s)
{
		switch (s->state)
		{
			case SESS_SYN:
				out("TCP SYN");
				break;
			case SESS_SYNACK:
				out("TCP SYNACK");
				break;
			case SESS_ACK:
				out("TCP ESTABLISHED");
				break;
			case SESS_FIN:
				out("TCP HALF CLOSED");
				break;
			case SESS_RST:
				out("TCP CLOSED RST");
				break;
			case SESS_FIN2:
				out("TCP FIN CLOSED");
				break;
			case SESS_PARTIAL_TCP:
				out("TCP PARTIAL");
				break;
			case SESS_HALF_OPEN:
				out("TCP HALF_OPEN SCAN");
				break;
			case SESS_OVERCLOSE:
				out("TCP OVERCLOSED");
				break;
			case SESS_BLINDSPOOF:
				out("TCP BLINDSPOOF");
				break;
			case SESS_UDP_OPEN:
				if(s->proto == ICMP)
					out("ICMP REQUEST");
				else
					out("UDP REQUEST");
				break;
			case SESS_UDP_ESTA:
				if(s->proto == ICMP)
					out("ICMP ESTABLISHED");
				else
					out("UDP ESTABLISHED");
				break;
			case SESS_UDP_TIMED:
				if(s->proto == ICMP)
					out("ICMP CLOSED");
				else
					out("UDP CLOSED");
				break;
			
		}
}


/*!
 *  display session protocol
 * @param s the session to display
 * @see session_display_plain()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 */ 
void 	session_display_protocol_plain(t_session *s)
{
	t_protocol_info		*p;
	p = s->protocol;
	while(p)
	{
		out("[Protocol]");
		out(" %s%s%s", cl.yel, p->name, cl.clr);
		if (p->version[0] != '\0')
			out(" ver:%s%s%s", cl.cya, p->version, cl.clr);
		if (p->familly[0] != '\0')
			out(" familly:%s%s%s", cl.pur, p->familly, cl.clr);
		if (p->encrypted[0] != '\0')
			out(" %s%s%s", cl.gre, p->encrypted, cl.clr);
		if (p->additionnal[0] != '\0')
			out(" %s%s%s", cl.clr, p->additionnal, cl.clr);
		out("\n");
		p = p->next;
	}
}

/*!
 *  display session protocol in xml
 * @param s the session to display
 * @see session_display_xml()
 * \version 1.0
 * \date    Mar 2007
 * \author Elie
 * \attention
 */
void 	session_display_protocol_xml(t_session *s)
{
	t_protocol_info		*p;
	p = s->protocol;
	if(p == NULL)
		return;
	out("\t<protocols>\n");
	while(p)
	{
		out("\t\t<protocol name=\"%s\"  version=\"%s\"  familly=\"%s\"  additionnal=\"%s\"  encrypted=\"%s\"  nature=\"%d\" ></protocol_info>\n",
		p->name, p->version, p->familly, p->additionnal, p->encrypted, p->nature);
		p = p->next;
	}	
	out("\t</protocols>\n)");
}

/*!
 *  display session file
 * @param s the session to display
 * @see session_display_plain()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \attention
 */ 

void 	session_display_file_plain(t_session *s)
{
	t_file		*f;
	f = s->file;
	while(f)
	{
		out("[File]");
		if(f->name[0] != '\0')
			out(" [request] name:%s%s%s", cl.yel, f->name, cl.clr);
		if(f->extension[0] != '\0')
			out(" [content] ext:%s%s%s", cl.gre, f->extension, cl.clr);
		if (f->size)
			out(" size:%s%lld%s", cl.gre, f->size, cl.clr);
		if (f->familly[0]  != '\0')
			out(" familly:%s%s%s", cl.pur, f->familly, cl.clr);
		if (f->headers[0]  != '\0')
			out(" headers:%s%s%s", cl.cya, f->headers, cl.clr);
		if (f->additionnal[0]  != '\0')
			out(" %s%s%s", cl.clr, f->additionnal, cl.clr);
		out("\n");
		f = f->next;
	}
}

/*!
 *  display session protocol in xml
 * @param s the session to display
 * @see session_display_xml()
 * \version 1.0
 * \date    Mar 2007
 * \author Elie
 * \attention
 */

void 	session_display_file_xml(t_session *s)
{
	t_file		*f;
	f = s->file;
	if(f == NULL)
		return;
	out("\t<files>\n");
	while(f)
	{	
		out("\t\t<file session_id=\"%lld\"  name=\"%s\"  extension=\"%s\"  familly=\"%s\"  headers=\"%s\"  additionnal=\"%s\"  nature=\"%d\"  size=\"%lld\"  entropy=\"%lld\"  object_pkt_num=\"%d\"  object_len=\"%d\" ></file>\n",
		f->session_id, f->name, f->extension, f->familly, f->headers, f->additionnal, f->nature, f->size, f->entropy, f->object_pkt_num, f->object_len);
		f = f->next;	
	}
	out("\t</files>\n");
}

/*!
 * compare session by protocol
 * @param a the first session
 * @param b the second session
 * @see session_output()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 * \todo sorting in somewhat broken if limited to n sessions because what is the filtering criteria ?? we might need an extra option
 */ 


int cmp_session_proto(const void *a, const void *b)
{
	t_session *s1 = *(t_session **) (a);
	t_session *s2 = *(t_session **) (b);
	//sorting by protocol and after by ip and the by port if possible
	if (ntohl(s1->dst) == ntohl(s2->dst))
	{
		if(ntohs(s1->dport) == ntohs(s2->dport))
		{
			if (ntohl(s1->src) == ntohl(s2 ->src))
			{

				if (ntohs(s1->sport) < ntohs(s2->sport))
					return -1;
				else 
					return 1;
				
			} else {
				if (ntohl(s1->src) < ntohl(s2 ->src))
					return -1;
				else
					return 1;
			}
		} else	{
			if (ntohs(s1->dport) < ntohs(s2->dport))
				return -1;
			else 
				return 1;
		}
	} else {
		if (ntohl(s1->dst) < ntohl(s2 ->dst))
			return -1;
		else
			return 1;
	}
}



/*!
 * compare session by traffic
 * @param a the first session
 * @param b the second session
 * @see session_output()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 */ 

int cmp_session_traf(const void *a, const void *b)
{
	t_session *s1 = *(t_session **) (a);
	t_session *s2 = *(t_session **) (b);
	if((s1->bytes_in + s1->bytes_out) >= (s2->bytes_in + s2->bytes_out))
		return -1;
	return 1;
}

/*!
 * compare session by time
 * @param a the first session
 * @param b the second session
 * @see session_output()
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 */ 

int cmp_session_time(const void *a, const void *b)
{
	t_session *s1 = *(t_session **) (a);
	t_session *s2 = *(t_session **) (b);
	if(s1->start_time > s2->start_time)
		return -1;
	else if (s1->start_time == s2->start_time && s1->start_time_usec > s2->start_time_usec)
		return -1;
	return 1;
}
