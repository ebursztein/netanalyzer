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

extern	t_session	**sessions_list;
extern	t_analyze	analyze;
extern	t_option	option;
t_tabproto		protocols_list;
t_protocol		sorted_protocol[65535];
extern	t_term_color	cl;

_u32 analyze_protocol()
{
	die("using useless function : analyze protocol why ?");
	return 1;
}

int cmp_protocol(const void *a, const void *b)
{
	t_protocol *p1 = (t_protocol *) (a);
	t_protocol *p2 = (t_protocol *) (b);

	if(p1->bytes_in + p1->bytes_out >= p2->bytes_in + p2->bytes_out)
		return -1;
	else
		return 1;
}


void protocol_display(t_protocol p, char* name)
{
	//char 		traf_in[20];
	//char		traf_out[20];
	//char 		traf_total_in[20];
	//char		traf_total_out[20];
	char		obuff[512];;
	bzero(obuff, 512);
	///\todo fixe me output : server_req server_reply and so one
	/*
	if (option.xml)
	{
		snprintf(obuff,512,"<protocol><name>%s</proto><port>%d</port><bytes_in total=\"%d\">%d</bytes_in><bytes_out total=\"%d\">%d</bytes_out><packet_in total=\"%d\">%d</packet_in><packet_out total=\"%d\">%d<packet_out><conn>%d</conn><request total=\"%d\">%d</request><reply total=\"%d\">%d</reply><error total=\"%d\">%d</error></protocol>\n",
			 		name,
					ntohs(p.port),
					p.bytes_in,
					output_value_by_sec(p.bytes_in),
					p.bytes_out,
					output_value_by_sec(p.bytes_out),
					p.nb_pkt_in,
					output_value_by_sec(p.nb_pkt_in),
					p.nb_pkt_out,
					output_value_by_sec(p.nb_pkt_out),
					p.conn,
					p.request,
					output_value_by_sec(p.request),
					p.reply,
					output_value_by_sec(p.reply),
					p.error,
					output_value_by_sec(p.error)
					);
	} else {
		output_trafic_by_sec(p.bytes_in, traf_in);
		output_trafic_by_sec(p.bytes_out,traf_out);
		output_trafic(p.bytes_in, traf_total_in);
		output_trafic(p.bytes_out,traf_total_out);
		if (p.port)
			snprintf(obuff,512,"%s%s%s\t%s %5u\t%s%10s/s%s (%10s) %s%5d pkts/s%s (%5d) \t %s%10s /s%s (%10s) %s%5d pkts/s%s (%5d)\t %s%d/s%s/%s%d%s/%s%d%s/%s%d%s\n", 
				 	cl.clr,cl.yel,
					name,
					cl.cya,
					ntohs(p.port),
					cl.gre,
					traf_in,
					cl.clr,
					traf_total_in,
					cl.pur,
					output_value_by_sec(p.nb_pkt_in),
					cl.clr,
					p.nb_pkt_in,
					cl.red,
					traf_out,
					cl.clr,
					traf_total_out,
					cl.pur,
					output_value_by_sec(p.nb_pkt_out),
					cl.clr,
					p.nb_pkt_out,
					cl.gre,
					p.conn,
					cl.clr, cl.yel,
					p.request,
					cl.clr, cl.cya,
					p.reply,
					cl.clr, cl.red,
					p.error,
					cl.clr);
		else
			snprintf(obuff,512,"%s%s%s\t%s%10s/s%s (%10s) %s%5d pkts/s%s (%5d) \t %s%10s /s%s (%10s) %s%5d pkts/s%s (%5d)\t %s%d%s/%s%d%s/%s%d%s/%s%d%s\n", 
				 cl.clr,cl.yel,
				 name,
				 cl.gre,
				 traf_in,
				 cl.clr,
				 traf_total_in,
				 cl.pur,
				 output_value_by_sec(p.nb_pkt_in),
				 cl.clr,
				 p.nb_pkt_in,
				 cl.red,
				 traf_out,
				 cl.clr,
				 traf_total_out,
				 cl.pur,
				 output_value_by_sec(p.nb_pkt_out),
				 cl.clr,
				 p.nb_pkt_out,
				 cl.gre,
				 p.conn,
				 cl.clr, cl.yel,
				 p.request,
				 cl.clr, cl.cya,
				 p.reply,
				 cl.clr, cl.red,
				 p.error,
				 cl.clr);
	}
	out(obuff);
	*/
}


void protocol_output(_u8 type, _s32 limit)
{
	_u32	max, i;
	
	if (option.xml)
		out("<protocols>");
	else
		out("###Protocol report###\nProto\t  Port\t                In /s (total)            \t         Out /s  (total)\t                   Conn/Req/Rep/Err/\n\n");
	//IP
	if(protocols_list.ip.nb_pkt_in || protocols_list.ip.nb_pkt_out)
		protocol_display(protocols_list.ip, "ip");
	
	//ARP
	if(protocols_list.arp.nb_pkt_in || protocols_list.arp.nb_pkt_out)
		protocol_display(protocols_list.arp, "arp");
	
	//ICMP
	if(protocols_list.icmp.nb_pkt_in || protocols_list.icmp.nb_pkt_out)
		protocol_display(protocols_list.icmp, "icmp");
	
	//total TCP
	if(protocols_list.ttcp.nb_pkt_in || protocols_list.ttcp.nb_pkt_out)
		protocol_display(protocols_list.ttcp, "total tcp");	
	
	if(protocols_list.tudp.nb_pkt_in || protocols_list.tudp.nb_pkt_out)
		protocol_display(protocols_list.tudp, "total udp");
	
	if(protocols_list.other.nb_pkt_in || protocols_list.other.nb_pkt_out)
		protocol_display(protocols_list.other, "other");
	
	if (!option.xml)
		out("\n                               ----TCP by port---\n\n");
	
	//limiting output if requested
	if (analyze.protocol > 0)
		max = analyze.session;
	else
		max = 65535;

	qsort(protocols_list.tcp, 65535, sizeof(t_protocol), cmp_protocol);
	for (i = 0; i < max; i++)
		if(protocols_list.tcp[i].nb_pkt_in || protocols_list.tcp[i].nb_pkt_out)
			protocol_display(protocols_list.tcp[i], "tcp");
	
	if (!option.xml)
		out("\n                              ----UDP by port---\n\n");
	
	qsort(protocols_list.udp, 65535, sizeof(t_protocol), cmp_protocol);
	for (i = 0; i < max; i++)
		if(protocols_list.udp[i].nb_pkt_in || protocols_list.udp[i].nb_pkt_out)
			protocol_display(protocols_list.udp[i], "udp");
	if (option.xml)
		out("</protocols>");
	return;
}

void protocol_clean()
{
	bzero(&protocols_list, sizeof(protocols_list));
	return;
}

void protocol_add_session(t_session *s)
{
	t_protocol	*p = NULL;
	t_protocol	*t = NULL; //for ttcp and tupd
	//selecting the appropriate protocol
	if (option.debug == 11)
		printf("Protocol adding sessions with protocol %d amd port %u\n", s->proto, ntohs(s->dport));
	
	if (s->proto >= TCP) {
		p = &protocols_list.tcp[s->dport];
		t = &protocols_list.ttcp;
	} else if (s->proto >= UDP && s->proto < TCP) {
		p = &protocols_list.udp[s->dport];
		t = &protocols_list.tudp;
	} else if (s->proto == ICMP) {
		p = &protocols_list.icmp;
	} else	if (s->proto == ARP)	{
		p = &protocols_list.arp;
	} else if (s->proto == IP ) {
		p = &protocols_list.ip;
	} else {
		p = &protocols_list.other;
	}

	//adding a connection 
	  ///\todo FIXME : do we need to count every connection or do we remove finished one.
	p->conn       	+= 1;
	p->nb_pkt_in  	+= s->nb_pkt_in;
	p->nb_pkt_out 	+= s->nb_pkt_out;
	p->bytes_in   	+= s->bytes_in;
	p->bytes_out  	+= s->bytes_out;
	p->file_client	+= s->file_client;
	p->file_server	+= s->file_server;
	p->req_client	+= s->req_client;
	p->req_server	+= s->req_server;
	p->rep_client	+= s->rep_client;
	p->rep_server	+= s->rep_server;
	p->err_client	+= s->err_client;
	p->err_server	+= s->err_server;
	p->port       	= s->dport;

	//optionnaly summing the total
	if(!t)
		return;
	
	t->conn       	+= 1;
	t->nb_pkt_in  	+= s->nb_pkt_in;
	t->nb_pkt_out 	+= s->nb_pkt_out;
	t->bytes_in   	+= s->bytes_in;
	t->bytes_out  	+= s->bytes_out;
	t->file_client	+= s->file_client;
	t->file_server	+= s->file_server;
	t->req_client	+= s->req_client;
	t->req_server	+= s->req_server;
	t->rep_client	+= s->rep_client;
	t->rep_server	+= s->rep_server;
	t->err_client	+= s->err_client;
	t->err_server	+= s->err_server;
	return;
}

void protocol_stating()
{
	_u32 i;
	for(i=0; i < analyze.session_stated; i++)
	{
		if (sessions_list[i])
			protocol_add_session(sessions_list[i]);
	}
	return;
}

void protocol_init()
{
	bzero(&protocols_list, sizeof(protocols_list));
	return;
}
