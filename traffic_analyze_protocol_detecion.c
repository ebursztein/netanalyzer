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
 *       \file traffic_analyze_protocol_detecion.c
 *       \brief The application detection algorithm
 *
 *	 The set of function used by the appliaciton detection algorittm based on  multiples discriminator/patter feedbacked
 *	 
 *       \author  Elie
 *       \version 1.1
 *	 \see Online traffic inspection article
 *       \date    Jun 2007
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
#include "headers/pattern_inspection.h"
t_option	option;
t_tuning	tuning;
void detection_add_pattern(t_session_protocol *proto, t_session *s, char *protocol_name, _u32 guess_probability);
void detection_new_pattern(t_session *s, char *protocol_name, _u32 guess_probability);
t_session_protocol *detection_get_proto(t_session *s, char *protocol_name);
_u32 detection_protocol_proba(t_session *s, t_session_protocol *proto, _u32 total_pattern_average , _u32 total_pattern,  _u8 total_porthint, _u32 total_profile);
void detection_select_protocol(t_session *s);


void detection_protocol_pattern(t_session *s, t_pkt *p, char *protocol_name, _u32 guess_probability)
{
	t_session_protocol	*proto;
	
	if(option.debug == 31)
		printf("Signature feedbacked :%s confidence:%d\n", protocol_name, guess_probability);
	s->proto_num_pattern++;
	if ((proto = detection_get_proto(s, protocol_name)) == NULL)
		detection_new_pattern(s, protocol_name, guess_probability);
	else
		detection_add_pattern(proto, s, protocol_name, guess_probability);
	
	//dynamic content insepction !
	detection_select_protocol(s);
	return;
}

void detection_add_pattern(t_session_protocol *proto, t_session *s, char *protocol_name, _u32 guess_probability)
{
	_u32 score;
	score  = s->proto_num_pattern *  guess_probability;
	proto->num_pattern++;
	proto->score_pattern += score;
}

t_session_protocol *detection_get_proto(t_session *s, char *protocol_name)
{
	t_session_protocol *proto;
	proto = s->proto_candidat;
	while(proto)
	{	
		if (strcmp(protocol_name, proto->name) == 0)
			return proto;
		proto = proto->next;
	}
	return NULL;
}

void detection_new_pattern(t_session *s, char *protocol_name, _u32 guess_probability)
{
	t_session_protocol *proto = NULL;
	proto = xmalloc(sizeof(t_session_protocol));
	bzero(proto, sizeof(t_session_protocol));
	strncpy(proto->name, protocol_name, BUFF_S);
	detection_add_pattern(proto, s, protocol_name, guess_probability);
	proto->next = s->proto_candidat;
	s->proto_candidat = proto;
}

void detection_new_port(t_session *s, char *protocol_name, _u32 guess_probability)
{
	t_session_protocol *proto = NULL;
	proto = xmalloc(sizeof(t_session_protocol));
	bzero(proto, sizeof(t_session_protocol));
	strncpy(proto->name, protocol_name, BUFF_S);
	proto->next = s->proto_candidat;
	s->proto_candidat = proto;
	proto->score_porthint = guess_probability;
	proto->num_porthint++;
	if(strcmp(protocol_name, "n/a") != 0 )
		s->proto_num_porthint++;
	//Dynamic detection !
	detection_select_protocol(s);
}



_u32 detection_protocol_proba(t_session *s, t_session_protocol *proto, _u32 total_pattern_average , _u32 total_pattern,  _u8 total_porthint, _u32 total_profile)
{
	float	dividend	= 0;
	float	divisor 	= 0;
	float	score		= 0;
	
	assert(tuning.weight_port 	!= 0);
	assert(tuning.weight_pattern 	!= 0);
	assert(tuning.weight_profile 	!= 0);
	//proba port
	proto->proba_porthint =  proto->score_porthint;
	
	if (option.debug == 31)
		printf("%lld:", s->id);
	//proba according to pattern
	if(proto->score_pattern) {
		proto->proba_pattern = proto->score_pattern;
	
		if (option.debug == 31)
			printf("[pattern] name:%s nummatch:%d scorepattern:%d total:%d ->", proto->name, proto->num_pattern, proto->score_pattern, total_pattern);
	
		proto->proba_pattern /= (total_pattern_average * 100);
		proto->proba_pattern = (proto->proba_pattern * 100);
		
		if (option.debug == 31)
			printf("score:%d ", (int)(proto->proba_pattern));
	}
	
	//proba profile
	//
	
	dividend  = tuning.weight_port *  proto->proba_porthint;
	dividend += tuning.weight_pattern * proto->proba_pattern;
	dividend += tuning.weight_profile * proto->proba_profile;
	
	if(total_porthint && dividend)
		divisor  += tuning.weight_port;
	
	if(total_pattern && dividend)
		divisor  += tuning.weight_pattern;
	
	if(dividend)
		score = dividend / divisor;
	else
		score = 0;
	
	proto->proba = (int)(score);
	if (option.debug == 31)
		printf("[port] total:%d proba:%d nb:%d score:%d [result] weight_port:%d weight_profile:%d weight_pattern:%d  dividend:%f divisor:%f proba:%f [result]%d\n", total_porthint, proto->score_porthint, proto->num_porthint, (int)(proto->proba_porthint), tuning.weight_port, tuning.weight_profile, tuning.weight_pattern, dividend, divisor, score, proto->proba);
	return	proto->proba;
}

void detection_select_protocol(t_session *s)
{
	t_session_protocol 	*proto;
	_u32			total_pattern, proba;
	
	assert (s->proto_candidat != NULL);
	
	total_pattern = ((s->proto_num_pattern * (s->proto_num_pattern + 1)) / 2); //(n(n-1))/2)
	proto = s->proto_candidat;
	//init
	proba = detection_protocol_proba(s, proto, total_pattern, s->proto_num_pattern, s->proto_num_porthint, s->proto_num_profile);
	s->guess_probability = proba;
	s->guessed_protocol = proto;
	proto = proto->next;
	while(proto != NULL)
	{	
		//found a better one ??
		if((proba = detection_protocol_proba(s, proto, total_pattern, s->proto_num_pattern, s->proto_num_porthint, s->proto_num_profile)) > s->guess_probability)
		{
			s->guess_probability 	= proba;
			s->guessed_protocol 	= proto;
		}
		proto = proto->next;
	}
}
