/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/*
 Gateway function analysis
*/

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
extern	t_host		**hosts_list;
extern	t_hash		*hosts;

t_gateway					*gates;


int cmp_host_by_arp(const void *a, const void *b)
{
	int		res;
	t_host *h1 = *(t_host **) (a);
	t_host *h2 = *(t_host **) (b);
	//sorting by arp
	res = memcmp(h1->arp,h2->arp, ETHER_ALEN);
	if (!res)
	{
		h1->infos = h1->infos | HOST_GW;
		h2->infos = h2->infos | HOST_GW;
		return -1;
	} else 
		return res;
}


void gateway_detect()
{
//	_u32	i;
	//cleaning out my closet
	//if (gates)
		//		free(gates);
	//gates = (t_gateway *)malloc(sizeof(t_gateway) * hosts->entrycount);
	//bzero(gates, sizeof(t_gateway)*hosts->entrycount);
	qsort(hosts_list, hosts->entrycount, sizeof(t_host*), cmp_host_by_arp);
/*	for(i = 0;i < hosts->entrycount ;i++)
		{
			if (hosts_list[i]);
			{
				if(host_list[i +1])
					if(!(hosts_list[i]->arp
			}
		}*/
}
