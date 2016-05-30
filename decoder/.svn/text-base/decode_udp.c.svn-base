/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Contributors: Poluc
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

extern	t_option option;

t_pkt	*decode_udp(t_pkt *entry)
{
#ifdef DEBUG_UDP
	struct in_addr	tmp;
#endif
	if ((entry->len - entry->decoded_len) < (UDP_HLEN))
	{
		entry->pkt_proto = UDP_TRUNKED; 
		return entry;
	}

	entry->udp = (t_udp *)(entry->buf + entry->decoded_len);
	entry->decoded_len += UDP_HLEN;
  	entry->pkt_proto = UDP;
	
	//Payload len and pointer
	entry->payload = (char *)(entry->buf + entry->decoded_len);
	entry->payload_len = entry->len - entry->decoded_len;


	/* old broken way to find a layer 7 decoder
	if (udp_proto_by_port[ntohs(entry->udp->sport)] != NULL)
	  entry = udp_proto_by_port[ntohs(entry->udp->sport)]->decode_proto(entry);
	else if (udp_proto_by_port[ntohs(entry->udp->dport)] != NULL)
	  entry = udp_proto_by_port[ntohs(entry->udp->dport)]->decode_proto(entry);
	*/

/*
#ifdef DEBUG_UDP
	else
	  fprintf(stderr, "Unknown high level UDP protocols ports: %d and %d\n", \
	    ntohs(entry->udp->sport), ntohs(entry->udp->dport));
#endif

#ifdef DEBUG_UDP
	fprintf(stderr, "udp_proto_by_port[sport].proto = %s\n",\
	  udp_proto_by_port[ntohs(entry->udp->sport)]->proto);
	fprintf(stderr, "udp_proto_by_port[dport].proto = %s\n",\
	  udp_proto_by_port[ntohs(entry->udp->dport)]->proto);
#endif
*/
	return entry;
}
