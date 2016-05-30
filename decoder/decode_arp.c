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
#include "../headers/sanity.h"

extern	t_option	option;
extern	t_analyze	analyze;

t_pkt	*decode_arp(t_pkt *entry)
{
	_u32 ip = 0;
  if ((entry->len - entry->decoded_len) < ARP_HLEN)
  {
	  		entry->pkt_proto = ARP_TRUNKED;
			return entry;
  }
  entry->arp = (t_arp *)(entry->buf + entry->decoded_len);
  entry->decoded_len += ARP_HLEN;
  //Payload len and pointer
  entry->payload = (char *)(entry->buf + entry->decoded_len);
  entry->payload_len = entry->len - entry->decoded_len;
  entry->pkt_proto = ARP;
	//bind arp to ip used in gateway detection
	if (ntohs(entry->arp->op) == ARP_OP_REPLY)
	{ 
	 	ip |= entry->arp->spa[3]& 0xff;
		ip = ip << 8;
		ip |= entry->arp->spa[2]& 0xff;
		ip = ip << 8;
		ip |= entry->arp->spa[1]& 0xff;
		ip = ip << 8;
		ip |= entry->arp->spa[0]& 0xff;
		host_set_option(ip, HOST_SELFARP);
	}
	return entry;
}
