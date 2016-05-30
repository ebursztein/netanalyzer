/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/*!
 *       \file traffic_analyze_function.c
 *       \brief Traffic inspection engine.
 *
 *	 Used to tell what type of traffic is going on in each stream using multiples discriminator/methods
 *	 Inspiration by pof, NMap, l7 filter and passive vulnerability scanner.
 *	 Backdoor detection, file match etc. Lot of people then
 *	 
 *       \author  Elie
 *       \version 1.0
 *	 \see Online traffic inspection article
 *       \date    July 2006
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include<assert.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
#include "headers/pattern_inspection.h"

extern t_option			option;
extern t_tab_services		services;
extern t_tuning			tuning;
extern t_analyze		analyze;

/*!
 * init the services structure.
 * \version 1
 * \date   July 2006
 * \author Elie
 * @see setup_default() 
 * @return nothing
 */
void services_init(void)
{
	bzero(&services, sizeof(services));
	services.arp.name = (char *)my_strndup("arp",3);
	services.ethernet.name = (char *)my_strndup("ethernet",8);
	services.ip.name = (char *)my_strndup("ip",2);
	services.icmp.name = (char *)my_strndup("icmp",4);
	services.unknown.name = (char *)my_strndup("unknown",7);
	
}

/*!
 * Return the service name according to it port.
 * \version 1
 * \date   Jun 2007
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @return nothing
 */

t_service *traffic_analyze_service_by_port(t_session *s, t_pkt *p)
{
	t_service 	*service = NULL;
	
	if(s->proto == ETHERNET)
		return &services.ethernet;
	else if (s->proto == ARP)
		return &services.arp;
	else if (s->proto == ICMP)
		return &services.icmp;
	else if (s->proto == IP)
		return &services.ip;
	if (s->proto >= UDP && s->proto < TCP) {
		return &services.udp[s->dport];
	
	} else if (s->proto >= TCP) {
		service = &services.tcp[s->dport];
		if(service->name != NULL)
			return service;
		else 
			if (s->state == SESS_PARTIAL_TCP)
				return &services.tcp[s->sport];
	}
	return NULL;
}


	
/*!
 * Used to provide a feedback form the traffic analyzer about the phase of the session
 * \version 1.0
 * \date   Dec 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @param next_phase the guest next_phase
 * @return nothing
 * \todo solve conflict feedback 
 */

void traffic_phase_feedback(t_session *s, t_pkt *p, _u8 next_phase)
{
	if(!p->ip)
		return;
	
	if (next_phase == CONTROL_PHASE) {
		if(s->src == p->ip->src)
			s->phase_client = CONTROL_PHASE;
		else 
			s->phase_server = CONTROL_PHASE;
	}
	
	if (next_phase == DATA_PHASE) {
		if(s->src == p->ip->src)
			s->phase_client = DATA_PHASE;
		else 
			s->phase_server = DATA_PHASE;
	}
	
		
}

/*!
 * Detect if the session has change phase.
 * \version 1.0
 * \date   Dec 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @return nothing
 * \todo put it in it own file 
*/
void traffic_phase_detection(t_session *s, t_pkt *p)
{
	int slop = 0;
	///!\todo add entropy and timing data to detect more accuratluy phase
	///!\todo add phase len brake set in config file in fact it has to be link with the mtu something like 33% of mtu is guess and 66% in control to data
	///!\todo count data send from the server to client but also from client to server
	///!\todo What about raw transfert such as ftp data ? (may work because of the tcp handshake with three len at 0)
	//ascending phase and above a thereold = we are getting a file
	
	
	///!\todo when traffic phase is fuckup what can we do ?
	
	if(p->ip->src == s->src)
	{
		slop = p->len - s->last_size_client;
		//server side
		if(slop > 0 && s->phase_client == CONTROL_PHASE)
		{
			if (p->len > PHASE_MINIMAL_SLOP_CONTROL_TO_DATA)
			{
				//first packet of the new phase
				if (option.debug == 20)
					printf("TE:session %lld CLIENT (CONTROL_PHASE ) phase change control->data. slop is :%d (%d,%d)\n",s->id, p->len - s->last_size_client, p->len, s->last_size_client);
				
				s->phase_client = DATA_PHASE;
				p->phase_client = DATA_PHASE;//prevent race condition on later analysis
				s->file_client++;
				s->file_client_len += p->payload_len;
				s->file_client_pkt_num++;
				s->file_client_last_len = p->payload_len;
				s->file_client_last_pkt_num = 1;
			}
		} else	if ( s->phase_client == DATA_PHASE && (slop < 0)) {
			 
			if ((p->len) < PHASE_MINIMAL_SLOP_DATA_TO_CONTROL)
			{
				//first packet of the new phase
				if (option.debug == 20)
					printf("TE:session %lld CLIENT (DATA_PHASE) phase change data->control. slop is :%d (%d,%d)\n",s->id, p->len - s->last_size_client, p->len, s->last_size_client);
				s->phase_client = CONTROL_PHASE;
				p->phase_client = CONTROL_PHASE;//prevent race condition on later analysis

			} else {
				s->file_client_len += p->payload_len;
				s->file_client_pkt_num++;
				s->file_client_last_len += p->payload_len;
				s->file_client_last_pkt_num++;
			}
		}	
		s->last_size_client = p->len;
		
		//better safe than sorruy
		if (s->phase_server == 0) s->phase_server = CONTROL_PHASE;
		if (s->phase_client == 0) s->phase_client = CONTROL_PHASE;
		if (p->phase_server == 0) p->phase_server = CONTROL_PHASE;
		if (p->phase_client == 0) p->phase_client = CONTROL_PHASE;
		
		return;
	} else {
		slop = p->len - s->last_size_server;
		//server side
		if(slop > 0 && s->phase_server == CONTROL_PHASE)
		{
			if (p->len > PHASE_MINIMAL_SLOP_CONTROL_TO_DATA)
			{
				//first packet of the new phase
				if (option.debug == 20)
					printf("TE:session %lld SERVER (CONTROL_PHASE ) phase change control->data. slop is :%d (%d,%d)\n",s->id, p->len - s->last_size_server, p->len, s->last_size_server);
				
				s->phase_server = DATA_PHASE;
				p->phase_server = DATA_PHASE;//prevent race condition on later analysis
				s->file_server++;
				s->file_server_len += p->payload_len;
				s->file_server_pkt_num++;
				s->file_server_last_len = p->payload_len;
				s->file_server_last_pkt_num = 1;
			} else {
				//if (option.debug == 20)
				//	printf("TE:session %lld SERVER (CONTROL_PHASE) slop under break slop is :%d (%d,%d)\n",s->id, p->len - s->last_size_server, p->len, s->last_size_server);
			}
		} else	if ( s->phase_server == DATA_PHASE && (slop < 0)) {
			 
			if ((p->len) < PHASE_MINIMAL_SLOP_DATA_TO_CONTROL)
			{
				//first packet of the new phase
				if (option.debug == 20)
					printf("TE:session %lld SERVER (DATA_PHASE) phase change data->control. slop is :%d (%d,%d)\n",s->id, p->len - s->last_size_server, p->len, s->last_size_server);
				s->phase_server = CONTROL_PHASE;
				p->phase_server = CONTROL_PHASE;//prevent race condition on later analysis

			} else {
				s->file_server_len += p->payload_len;
				s->file_server_pkt_num++;
				s->file_server_last_len = p->payload_len;
				s->file_server_last_pkt_num = 1;
			}
		}	
		s->last_size_server = p->len;
		
		//better safe than sorruy
		if (s->phase_server == 0) s->phase_server = CONTROL_PHASE;
		if (s->phase_client == 0) s->phase_client = CONTROL_PHASE;
		if (p->phase_server == 0) p->phase_server = CONTROL_PHASE;
		if (p->phase_client == 0) p->phase_client = CONTROL_PHASE;
		
		return;
	}


}

/*!
 * Entry point of the traffic inspection engine.
 * \version 1.1
 * \date   Dec 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @return nothing
 */

void traffic_analyze(t_session *s, t_pkt *p)
{
	assert(p != NULL && p->pkt_proto > 0);
	assert(s != NULL);
	assert(s->proto > 0);
	
	

	
	//phase detection
	if(s->src || s->dst)
		traffic_phase_detection(s, p);
	
	//check if we are in learning phase if so dumping profile and return
	if(tuning.dump_profile)
	{
		if(p->payload_len)
			traffic_profile_dump(p->s,p);
		return;
	}
	//no ? well let's see what type of stream this is 
	
	//be sure that we are on l7 protocol
	//if(p->proto < UDP)
	//	return;
	//do we have matched by it's port ?
	if(!s->service)
	{
		s->service = traffic_analyze_service_by_port(s, p);
		if(option.debug == 27)
			printf("Traffic analyze found  service name %s\n",s->service->name);
		
		if (s->service)
		{
			if(s->service->name) {
				detection_new_port(s, s->service->name, tuning.port_heuristic_confidence);
			} else {
				//well "c'est la loose"
				detection_new_port(s, "unknown", 0);			
			}
		} else {
			s->service = &services.unknown;
			detection_new_port(s, "unknown", 0);
		}	
	}
	if(analyze.advanced == 0)
		return;
	
		//checking profile if needed
	if(tuning.useprofile)
	{
		traffic_analyze_by_profile(s, p);
	}
	
	//pattern inspection has it own thread



}

/*!
 * Used to stat request reply and error according to the match of rules
 * \version 1.0
 * \date   Dec 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @param host client or server
 * @param type error request or reply
 * @return nothing
 */
 
void traffic_analyze_stat(t_session *s, t_pkt *p, _u8 host, _u8 type)
{
	//client style
	     if (type == GROUP_REQ && HOST_FROM) s->req_client++;
	else if (type == GROUP_REP && HOST_FROM) s->rep_client++;
	else if (type == GROUP_ERR && HOST_FROM) s->err_client++; 
 	
	//server style
	     if (type == GROUP_REQ && HOST_TO) s->req_server++;
	else if (type == GROUP_REP && HOST_TO) s->rep_server++;
	else if (type == GROUP_ERR && HOST_TO) s->err_server++; 
}



void traffic_mtu_packet(t_pkt *p)
{
	_u16 mtu;
	assert(p->pkt_proto == ICMP);
	if (!(p->icmp->type == 3 && p->icmp->code == 4))
		return;
	mtu = p->payload[2] <<8;
	mtu += p->payload[3];
		//printf("MTU discovery :%d:%s\n", mtu,p->payload);
}

/*!
 * Evaluate the distance in hop of given host
 * 
 * Use for the moment the 2^x heuristic
 * 
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * @param ttl ttl value
 * @param os os name
 * @param version os version
 * @return hop distance
 */

int traffic_ttl_distance(_u8 ttl, char *os, char* version)
{
	int base = 0;
	
	     if(ttl > 128)	base = 256;
	else if(ttl > 64) 	base = 128;
	else if(ttl > 32) 	base = 64;
	else if(ttl > 16) 	base = 32;
	else if(ttl > 8) 	base = 16;
	else if(ttl > 4) 	base = 8;
	else if(ttl > 2) 	base = 4;
	else if(ttl > 1) 	base = 2;
	return base - ttl;
}
