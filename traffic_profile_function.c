/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"

extern	t_tuning	tuning;
/*!
 * Return the size of the packet.
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @see traffic_profile()
 * @return packet len
 */
_u32 get_len(t_pkt *p)
{
	return p->payload_len;
}


/*!
 * Return the time intervall between this packet and the previous in the same direction
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @see traffic_profile()
 * @return time intervall in usec
*/
_s64 get_stream_timing(t_pkt *p, t_session *s)
{
	_s64 res = 0;
	
	if (p->last_time == 0)
		return -1;
	if(p->ip->src == s->src)
	{
		if (p->last_time_out == 0)
			return -1;
		res =  ((p->time_capture - p->last_time_out) * 1000000) + p->time_capture_usec - p->last_time_out_usec;
		assert(res >= 0);
	} else {
		if (p->last_time_in == 0)
			return -1;
		res =  ((p->time_capture - p->last_time_in) * 1000000) + p->time_capture_usec - p->last_time_in_usec;
		assert(res >= 0);
	}
	return res;
}





/*!
 * Return the time intervall between this packet and the last packet from the other side
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @see traffic_profile()
 * @return time intervall in usec
 */
_s64 get_response_timing(t_pkt *p, t_session *s)
{
	_s64 res = 0;
	
	if (p->last_time == 0)
		return -1;
	if(p->ip->src == s->src)
	{
		if (p->last_time_in == 0)
			return -1;
		res =  ((p->time_capture - p->last_time_in) * 1000000) + p->time_capture_usec - p->last_time_in_usec;
		assert(res > 0);
	} else {
		if (p->last_time_out == 0)
			return -1;
		res =  ((p->time_capture - p->last_time_out) * 1000000) + p->time_capture_usec - p->last_time_out_usec;
		assert(res > 0);
	}
	return res;
}


/*!
 * return the computed profile of a packet.
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @see traffic_profile()
 * @return profile
 */

t_traffic_profile *traffic_profile_from_pkt(t_pkt *p)
{
	return NULL;
}


/*!
 * analyze the profile of the packet
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @see traffic_analyze()
 * @return profile
 */

void traffic_analyze_by_profile(t_session *s, t_pkt *p)
{
	
	return;
}

/*!
 * compute if the profile t match the profile p.
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param t profile to test
 * @param p reference profile
 * @see traffic_analyze_by_profile()
 * @return profile
 */

int traffic_profile_cmp(t_traffic_profile *t, t_traffic_profile *p)
{
	return 24;
}


/*!
 * dump the profile of every packet. Used for profile construction
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param p packet
 * @param s session of the packet
 * @see traffic_profile()
 * @return profile
 */
 
void traffic_profile_dump(t_session *s, t_pkt *p)
{	
	_u16 len, i, j;
	unsigned long freq[256];
	_s64 stream_timing, response_timing;
	unsigned char *pos;
	entropy_t e;
	entropy_t mm_e;
	entropy_t jk_e;
	entropy_t pan_e;
	
	bzero(freq, sizeof(freq));
	//Packet information
	if(p->pkt_proto == ARP)
		out("profile:protocol=ARP:");
	else if (p->pkt_proto == ICMP)
		out("profile:protocol=ICMP:");
	else if (p->pkt_proto >= UDP && s->proto < TCP)
		out("profile:protocol=UDP:");
	else 
		out("profile:protocol=TCP:");
	//we use the destination port because we are looking to aggregate by service
	out("port=%d:",ntohs(s->dport));
	//we add +1 because it's all the sessions packet already seen and this one . -3 is for tcp handshake
	out("session_pkt_num=%d:", (s->proto >= TCP) ? p->nb_pkt_out + p->nb_pkt_in - 3  + 1  : p->nb_pkt_out + p->nb_pkt_in + 1);
	///\todo fixme broadcast addr 0.0.0.0
	if(s->src)
	{
		if(p->ip->src == s->src)
			out("stream_way=%d:stream_pkt_num=%d:", TRAF_OUT, p->nb_pkt_out + 1);
		else
			out("stream_way=%d:stream_pkt_num=%d:", TRAF_IN, p->nb_pkt_in + 1);
	}
	//len  of the packet
	len = get_len(p);
	out("payload_len=%d:",len);
	
	//restrict len for analysis if needed
	if(tuning.profile_restrict_len > 0 && len > tuning.profile_restrict_len)
		len = tuning.profile_restrict_len;
	out("analyzed_len=%d:",len);
	
	//frequency
	assert(len > 0);
	for (pos =(unsigned char*) p->payload, i = 0; i < len; i++)
		freq[ *pos++ ]++;
	out("freq=");
	for(i = 0, j = 0; i < 256; i++)
	{	
		out("%ld;",freq[i]);
		j += freq[i];
	}
	assert(j == len);
	out(":");
	
	//Timing info
	if((stream_timing   = get_stream_timing(p, s)) > 0)
		out("timing=%lld:",stream_timing);
	else
		out("timing=0:");
	if((response_timing   = get_response_timing(p, s)) > 0)
		out("response=%lld:",response_timing);
	else
		out("response=0:");
	
	//Entropy
	COMP_ENT(freq, len, e);
	mm_e = compute_mm_entropy(e, freq, len);
	jk_e = compute_jk_entropy(e, freq, len);
	pan_e = compute_pan_entropy(e, freq, len);
	out("shannon_entropy=%20.18f:entropy_ratio=%6.4f:miller_madow_entropy=%20.18f:miller_madow_bias=%20.18f:jackknifed_entropy=%20.18f:jackknifed_bias=%20.18f:paninski_entropy=%20.18f:paninski_bias=%20.18f:",
	e,
	(len * e) / (len * 8.0) * 100.0,
	mm_e, mm_e - e,
	jk_e, jk_e - e,
	pan_e, pan_e - e);
	out("\n");
}
