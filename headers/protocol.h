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
 * Contains the protocols define
 */

#ifndef _protocol_H
#define _protocol_H 1
/* before decode */
#define NOTDECODED 		-1
/* screwed protocol */
#define	ETHERNET_TRUNKED	-2
#define	ARP_TRUNKED		-3
#define	IP_TRUNKED		-4
#define	TCP_TRUNKED		-5
#define	TCP_OVERLEN		-6
#define	UDP_TRUNKED		-7
#define	ICMP_TRUNKED		-8
#define	WIFI_TRUNKED		-9
/* Layer 2 - 3 protocol */

#define ETHERNET	1
#define WIFI		2
#define ARP		10
#define	IP		50

/* Layer 4 protocol */
#define ICMP		100
#define	UDP		500
#define	TCP		1000

/* UDP flux */
#define	OTHER_UDP	501
#define	DNS_UDP		502
#define	DHCP_UDP	503
#define	GAMESPY		504
#define	HL		505

/* TCP flux */
#define OTHER_TCP	1001
#define FTP		1002
#define SSH		1003
#define TELNET		1004	
#define SMTP		1005
#define DNS_TCP		1006
#define HTTP		1007
#define POP3		1008
#define NEWS		1009
#define SMB		1010	
#define HTTPS		1011
#define IRC		1012
#define FTP_DATA	1013
#define DHCP_TCP	1014
#define	IMAP		1015
#define	MYSQL		1016

#endif
