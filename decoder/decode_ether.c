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
extern	t_option option;

t_pkt	*decode_ether(t_pkt *entry)
{
	if ((entry->len - entry->decoded_len) < ETHER_HLEN)
	{
		entry->pkt_proto = ETHERNET_TRUNKED;
		return entry;
	}
	entry->ether = (t_ether *)(entry->buf);
	entry->decoded_len += ETHER_HLEN;
	//Payload len and pointer
	entry->payload = (char *)(entry->buf + entry->decoded_len);
	entry->payload_len = entry->len - entry->decoded_len;
	entry->pkt_proto = ETHERNET;
	
	/*printf("%02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x\n",
					 entry->ether->shost[0],
					 entry->ether->shost[1],
					 entry->ether->shost[2],
					 entry->ether->shost[3],
					 entry->ether->shost[4],
					 entry->ether->shost[5],
				 entry->ether->dhost[0],
				 entry->ether->dhost[1],
				 entry->ether->dhost[2],
				 entry->ether->dhost[3],
				 entry->ether->dhost[4],
				 entry->ether->dhost[5]);
*/
	switch (ntohs(entry->ether->type))
	{
	  case ETHER_TYPE_IP:
		decode_ip(entry);
	  break;
	  case ETHER_TYPE_ARP:
	  	decode_arp(entry);
	  break;
          #ifdef DEBUG_ETHER
	    fprintf(stderr, "Not an IP nor ARP packet\n");
          #endif
	}
	
	return entry;
}
