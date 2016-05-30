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
#include "../headers/protocol.h"
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"

extern	t_option option;

t_pkt	*decode_ip(t_pkt *entry)
{
    #ifdef DEBUG_IP
	struct in_addr	tmp;
    #endif
	if (entry->len - entry->decoded_len < IP_MIN_HLEN)
	{
		entry->pkt_proto = IP_TRUNKED;
		return entry;
	}
        //FIXME : check checksum IP and TCP
	entry->ip = (t_ip *)(entry->buf + entry->decoded_len);
	entry->decoded_len += IP_HL(entry->ip);
	//Payload len and pointer
	entry->payload = (char *)(entry->buf + entry->decoded_len);
	entry->payload_len = entry->len - entry->decoded_len;
	entry->pkt_proto = IP;

	//sanity
	//have the wrong flag... or no flag and offset -> padding is not good.
	if (entry->ip->fragoff & IP_FRAG_UNUSED || (entry->ip->fragoff & IP_MF && entry->ip->fragoff <<3))
		entry->sanity = entry->sanity | SANITY_IP_LEAK;
	switch(entry->ip->p)
	{
		case IP_PROTO_TCP :
			decode_tcp(entry);
			break;
		case IP_PROTO_UDP :
			decode_udp(entry);
			break;
		case IP_PROTO_ICMP :
			decode_icmp(entry);
			break;
		default :
                         #ifdef DEBUG_IP
                        tmp.s_addr = entry->ip->src;
                        fprintf(stderr, "IP: %s > ", inet_ntoa(tmp));
                        tmp.s_addr = entry->ip->dst;
                        fprintf(stderr, "%s:", inet_ntoa(tmp));
                        #endif
                        if(option.debug == 2)
			fprintf(stderr, "IP: Not a TCP, UDP nor ICMP packet\n");
	}
	return entry;
}
