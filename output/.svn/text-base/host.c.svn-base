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
 * \file user.c
 * \brief functions used for user ouput in the output thread
 * \author  Elie
 * \version 1.0
 * \date    Mar 2007
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

#define USER_STANDALONE 1
#define USER_SESSION	2

extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*hosts;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_host		**hosts_list;


void host_display_plain(t_host *h, _u8 type);
void host_display_xml(t_host *h, _u8 type);

int cmp_host_traff(const void *a, const void *b);

void host_output(_u8 type, _s32 limit)
{

	_u32 		 i, max;
	qsort(hosts_list, hosts->entrycount, sizeof(t_host*), cmp_host_traff);
	if (option.xml)
		out("<hosts>");
	else
		out("###  Host analyze\n\n");
	//limiting output if requested
	if (analyze.host > 0 && analyze.host < analyze.host_stated)
		max = analyze.host;
	else
		max = analyze.host_stated;
	//can't do it backward due to sorting
	for(i = 0;i < max; i++)
	{
		if (hosts_list[i])
		{
			if (option.xml)
				host_display_xml(hosts_list[i], 0);
			else
				host_display_plain(hosts_list[i], 0);
		}
	}
	if(option.xml)
		out("</hosts>");
}

/*!
 * used to display host information
 * @param h the host structure
 * @param type not used
 * @see host_output()
 * \version 1.1
 * \date   Mar  2007
 * \author Elie	
*/
void host_display_plain(t_host *h, _u8 type)
{
	///!\todo FIXME TTL
	struct 	in_addr		ip;
	char 			traf_in[BUFF_S];
	char			traf_out[BUFF_S];
	char 			traf_total_in[BUFF_S];
	char			traf_total_out[BUFF_S];;
	
	assert(h);
	
	ip.s_addr = h->ip;
	output_trafic_by_sec(h->bytes_in, traf_in);
	output_trafic_by_sec(h->bytes_out,traf_out);
	output_trafic(h->bytes_in, traf_total_in);
	output_trafic(h->bytes_out,traf_total_out);
	
	out("%5lld", h->id);
	out(" %s%15s%s",cl.yel, inet_ntoa(ip), cl.clr);

	//traff by sec
	out(" [traffic] I:%s%s/s%s %s%d%s pkt/s",cl.gre, traf_in, cl.clr, cl.pur, output_value_by_sec(h->nb_pkt_in), cl.clr); 
	out(" O:%s%s/s%s %s%d%s pkt/s",cl.cya, traf_out, cl.clr, cl.pur, output_value_by_sec(h->nb_pkt_out), cl.clr); 
	
	//layer 7
	if(h->hostname[0] != '\0')
		out("Host:%s%s%s",cl.yel,h->hostname,cl.clr);
	if(h->netbios_hostname[0] != '\0')
		out("netbios:%s%s%s",cl.blu,h->netbios_hostname,cl.clr);
	if(h->passive_os_type[0] != '\0')
		out("os:%s",cl.cya,h->passive_os_type,cl.clr);
	if(h->passive_os_version[0] != '\0')
		out("ver:%s",cl.yel,h->passive_os_version,cl.clr);
	
	out(" [L7] Con I:%s%d%s/O:%s%d%s Req:%s%d%s Rep:%s%d%s", cl.gre, h->conn_in, cl.clr,  cl.cya, h->conn_out, cl.clr, cl.gre, h->request, cl.clr, cl.cya, h->reply, cl.clr);
	if((h->error) > 0)
		out(" Err:%s%d%s", cl.clr, h->error, cl.red);

	/*
	snprintf(obuff,512,"%s%5lld %s%15s%s (%s%s)                %s%7s/s%s (%7s) %s%5d pkts/s%s (%5d) %s%7s/s%s (%7s) %s%5d pkts/s%s (%5d) %sin:%d out:%d%s  /%s%d%s/%s%d%s/%s%d%s ",
		 cl.clr, h->id, cl.yel, ipbuff, cl.clr, cl.cya,
			cl.clr,
			
			traf_total_in,
			cl.pur,
			output_value_by_sec(h->nb_pkt_in),
			cl.clr,
			h->nb_pkt_in,

			traf_total_out,
			cl.pur,
			output_value_by_sec(h->nb_pkt_out),
			cl.clr,
			h->nb_pkt_out,
			cl.clr,
			h->conn_in,
			h->conn_out,
			cl.clr, cl.yel,
			h->request,
			cl.clr, cl.cya,
			h->reply,
			cl.clr, cl.red,
			h->error,
			cl.clr);


		//arp here
		if((h->infos & HOST_GW) && (!(h->infos & HOST_SELFARP)))
								h->arp[0],
					h->arp[1],
					h->arp[2],
					h->arp[3],
					h->arp[4],
					h->arp[5],
					h->ethervendor ? h->ethervendor :  "",
     
			*/

		if(h->infos & HOST_SELFARP)
			out(" %slan%s", cl.pur, cl.clr);
		else
			out(" %swan%s distance %s%d%s",cl.cya, cl.clr, cl.gre, h->distance, cl.clr);
		if((h->infos & HOST_GW) && ((h->infos & HOST_SELFARP)) && h->arp_flip == 0)
			out(" Gateway");
		//if((h->infos & HOST_GW) && (!(h->infos & HOST_SELFARP)))
		if(((h->infos & HOST_SELFARP)))
		{
			if(h->ethervendor)
				out(" %s%s%s (%02x:%02x:%02x)",cl.yel, h->ethervendor, cl.clr, h->arp[3], h->arp[4], h->arp[5]);
			else
				out(" %02x:%02x:%02x:%02x:%02x:%02x", h->arp[0], h->arp[1], h->arp[2], h->arp[3], h->arp[4], h->arp[5]);
		}
		out("\n");

}

/*!
 * used to display host information in xml
 * @param h the host structure
 * @param type not used
 * @see host_output()
 * \version 1.1
 * \date   Mar  2007
 * \author Elie	
*/
void host_display_xml(t_host *h, _u8 type) {
	out("<host ip=\"%d\"  id=\"%lld\"  crc=\"%lld\"  arp=\"%d\"  ethervendor=\"%s\"  arp_flip=\"%d\"  sanity=\"%d\"  last_time=\"%lld\"  ttl=\"%d\"  infos=\"%d\"  distance=\"%d\"  hostname=\"%s\"  netbios_hostname=\"%s\"  passive_os_type=\"%s\"  passive_os_version=\"%s\"  conn_in=\"%d\"  conn_out=\"%d\"  nb_pkt_in=\"%d\"  nb_pkt_out=\"%d\"  bytes_in=\"%d\"  bytes_out=\"%d\"  request=\"%d\"  reply=\"%d\"  error=\"%d\" ></host>\n",
	h->ip, h->id, h->crc, h->arp, h->ethervendor, h->arp_flip, h->sanity, h->last_time, h->ttl, h->infos, h->distance, h->hostname, h->netbios_hostname, h->passive_os_type, h->passive_os_version, h->conn_in, h->conn_out, h->nb_pkt_in, h->nb_pkt_out, h->bytes_in, h->bytes_out, h->request, h->reply, h->error); 

}

int cmp_host_traff(const void *a, const void *b)
{
	t_host *h1 = *(t_host **) (a);
	t_host *h2 = *(t_host **) (b);
	//sorting by protocol and after by ip and the by port if possible
	if ((h1->bytes_in + h1->bytes_out) > (h2->bytes_in + h2->bytes_out))
		return -1;
	else
		return 1;
}

