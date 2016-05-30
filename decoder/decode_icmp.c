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

#ifdef DEBUG_ICMP
static void	*decode_icmp_unreachable(t_pkt *);
#endif

extern	t_option option;



t_pkt	*decode_icmp(t_pkt *entry)
{;
        #ifdef DEBUG_ICMP
	struct in_addr	tmp;
        #endif
	if (entry->len - entry->decoded_len < ICMP_HLEN)
	{	
		entry->pkt_proto = ICMP_TRUNKED; 
		return entry;
	}
	entry->icmp = (t_icmp *)(entry->buf + entry->decoded_len);
	entry->decoded_len += ICMP_HLEN;
	entry->pkt_proto = ICMP;
	 //Payload len and pointer
	entry->payload = (char *)(entry->buf + entry->decoded_len);
	entry->payload_len = entry->len - entry->decoded_len;
	if (entry->ip->tos && entry->icmp->type == ICMP_TYPE_ECHO_REQUEST)
		entry->sanity = entry->sanity | SANITY_ICMP_FINGER;  
	return entry;
}
