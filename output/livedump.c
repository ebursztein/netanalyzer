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
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"
#include "../headers/pattern_inspection.h"

extern	t_term_color	cl;

//ikso
void livedump_display_error(t_error *e, t_pkt *p, t_session *s)
{
	//only fresh data
	if(e->frequency == 1)
		error_display_plain(e,TYPE_ERROR);
}

void livedump_display_soft(t_software *o)
{
	//only fresh data
	if(o->conn == 1)
		software_display_plain(o, SOFT_STANDALONE);
}

void livedump_display_newsess(t_session *s)
{
	struct 	in_addr		src;
	struct 	in_addr		dst;

	if(s->proto >= IP)
	{
		src.s_addr = s->src;
		dst.s_addr = s->dst;
	}
	
	out("%s[Connection]%s", cl.blu, cl.clr);
				
	//client
	out("%15s:%s%5d%s",inet_ntoa(src), cl.pur, ntohs(s->sport), cl.clr);
	    
	//server
	out("->%15s:%s%5d%s", inet_ntoa(dst), cl.pur, ntohs(s->dport), cl.clr);
	
	out("%s%s%s",cl.yel, s->guessed_protocol, cl.clr);
	//fancy for proba
	     if (s->guess_probability >= 75) out("%s", cl.gre);
	else if (s->guess_probability >= 50) out("%s", cl.yel);
	else 					out("%s", cl.red);
	out(" %d\%", s->guess_probability);
	
	out("\n");
}
