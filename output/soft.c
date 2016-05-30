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
 * \file soft.c
 * \brief functions used for soft ouput in the output thread
 * \author  Elie
 * \version 1.0
 * \date    Feb 2007
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
extern	t_hash		*softwares;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_software	**softwares_list;

void software_display_xml(t_software *o, _u8 type);
int cmp_software_ip(const void *a, const void *b);

void software_output(_u8 type, _s32 limit)
{


	_u32 		 i, max;
	qsort(softwares_list, softwares->entrycount, sizeof(t_software*), cmp_software_ip);
	if (option.xml)
		out("<sotfwares>");
	else 
		out("####softwares reports####\n");
	//limiting output if requested
	if (analyze.software > 0 && analyze.software < analyze.software_stated)
		max = analyze.software;
	else
		max = analyze.software_stated;
	//can't do it backward due to sorting
	if (max == 0)
	 	return;
	for(i = 0;i < max; i++)
	{
		if (softwares_list[i])
		{
			if(option.xml)
				software_display_xml(softwares_list[i], SOFT_STANDALONE);
			else
				software_display_plain(softwares_list[i], SOFT_STANDALONE);
		}
	}
	if(option.xml)
		out("</softwares>");
}

/*!
 * used to display software information for both standlone view and session one
 * @param o the software structure
 * @param type standalone or session view
 * @see session_output()
 * \version 1.1
 * \date   Feb  2007
 * \author Elie	
*/
void software_display_plain(t_software *o, _u8 type)
{
	struct 	in_addr		ip;
	assert(o);
	assert(o->ip);
	ip.s_addr = o->ip;
	
	assert(o);
	
	if (o->type == SOFT_CLIENT)
		out("[Client]");
	else
		out("[Server]");
	if(type == SOFT_STANDALONE)
	{
		if (o->ip);
			out(" %s", inet_ntoa(ip));
	
		if (o->type == SOFT_SERVER)
			out(":%d", ntohs(o->port));
	}
	if (o->hostname[0] != '\0')
		out(" (%s%s%s)", cl.cya, o->hostname, cl.clr);
	
	out(": %s%s%s", cl.yel, o->product, cl.clr);
	
	if (o->version[0] != '\0')
		out(" ver:%s%s%s", cl.gre, o->version, cl.clr);
	
	if (o->familly[0] != '\0')
		out(" familly:%s%s%s", cl.pur, o->familly, cl.clr);
	
	if (o->ostype[0] != '\0')
		out(" OS:%s%s%s", cl.cya, o->ostype, cl.clr);
	
	if (o->devicetype[0] != '\0')
		out(" Type:%s%s%s", cl.cya, o->devicetype, cl.clr);
		
	if (o->info[0] != '\0')
		out(" %s%s%s", cl.clr, o->info, cl.clr);
	
	out(" nbseen:%s%d%s", cl.gre, o->conn, cl.clr);
	out("\n");
	
}


/*!
 * used to display software information for both standlone view and session one in xml
 * @param o the software structure
 * @param type standalone or session view
 * @see session_output()
 * \version 1.0
 * \date   Mar  2007
 * \author Elie	
*/

void software_display_xml(t_software *s, _u8 type)
{
	if(type == SOFT_SESSION)
		out("\t");
	out("\t<software id=\"%lld\"  host_id=\"%lld\"  proto=\"%d\"  ip=\"%d\"  port=\"%d\"  crc=\"%lld\"  crc_version=\"%lld\"  sanity=\"%d\"  first_seen=\"%lld\"  first_seen_usec=\"%lld\"  last_seen=\"%lld\"  last_seen_usec=\"%lld\"  conn=\"%d\"  type=\"%d\"  nature=\"%d\"  product=\"%s\"  version=\"%s\"  protocol=\"%s\"  familly=\"%s\"  info=\"%s\"  hostname=\"%s\"  ostype=\"%s\"  devicetype=\"%s\" ></software>\n",
	s->id, s->host_id, s->proto, s->ip, s->port, s->crc, s->crc_version, s->sanity, s->first_seen, s->first_seen_usec, s->last_seen, s->last_seen_usec, s->conn, s->type, s->nature, s->product, s->version, s->protocol, s->familly, s->info, s->hostname, s->ostype, s->devicetype);

}


/*!
 * used into the session output to print software information
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Feb  2007
 * \author Elie	
 * \todo move this to a generic output that can be use for session and mapping 
 */
void 	software_session_display_plain(t_session *s)
{
	t_software	*o;

	o = s->server;
	while(o)
	{
		software_display_plain(o, SOFT_SESSION);
		//printf("\tServer %s %s %s %s\n", o->familly ? o->familly : "", o->product, o->version ? o->version : "", o->ostype ? o->ostype : "", o->info? o->info : "");
		o = o->next;
	}
	
	o = s->client;
	while(o)
	{
		software_display_plain(o, SOFT_SESSION);
		o = o->next;
	}
}

/*!
 * used into the session output to print software information in XML
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Feb  2007
 * \author Elie	
 * \todo move this to a generic output that can be use for session and mapping 
 */
void 	software_session_display_xml(t_session *s)
{
	t_software	*o;

	o = s->server;
	if(o)
		out("\t<clientSoftware>\n");
	while(o)
	{
		software_display_xml(o, SOFT_SESSION);
		//printf("\tServer %s %s %s %s\n", o->familly ? o->familly : "", o->product, o->version ? o->version : "", o->ostype ? o->ostype : "", o->info? o->info : "");
		o = o->next;
	}
	if(o)
		out("\t</clientSoftware>\n");
	
	o = s->client;
	if(o)
		out("\t<serverSoftware>\n");
	while(o)
	{
		software_display_plain(o, SOFT_SESSION);
		o = o->next;
	}
	if(o)
		out("\t<serverSoftware>\n");
}


int cmp_software_ip(const void *a, const void *b)
{
	t_software *o1 = *(t_software **) (a);
	t_software *o2 = *(t_software **) (b);
	//sorting ip and then by num of conn
	if(o1->ip > o2->ip)					return -1;
	else if(o1->ip > o2->ip)				return -1;
	else if(o1->port > o2->port && o1->type == SOFT_SERVER)  return -1;
	else if(o1->conn > o2->conn)				return -1;
	return 1;
}

