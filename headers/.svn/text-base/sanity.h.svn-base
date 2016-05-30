/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/

/*Catch as many as possible strange thing during analysis*/
#ifndef _HAVE_SANITY_H
#define _HAVE_SANITY_H
#define SANITY_ARP_TRUNK                 	0x0001
#define SANITY_IP_TRUNK	              		0x0002
#define SANITY_TCP_TRUNK                 	0x0004
#define SANITY_UDP_TRUNK                	0x0008
#define SANITY_ICMP_TRUNK                 	0x0010
#define	SANITY_TCP_FINGER			0x0020 //Invalide combinaison used for tcp fingerprint
#define	SANITY_TCP_UNUSED_FLAG			0x0040 //unused flag used ..
#define SANITY_TCP_OTHER_ERROR_FLAG  		0x0080 //2^8
#define SANITY_ICMP_FINGER 			0x0100 //Specific combinaison used for icmp fingerprint
#define	SANITY_IP_FRAG				0x0200
#define	SANITY_IP_LEAK				0x0400	//frag offset not set but field set ...
#define SANITY_TCP_LEAK				0x0800	//urg flag not set buf field is set
#define SANITY_TCP_HL				0x1000	//tcp header is to long
#endif
