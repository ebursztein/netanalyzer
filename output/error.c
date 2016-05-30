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
 * \file error.c
 * \brief functions used for error and event ouput in the output thread
 * \author  Elie
 * \version 1.0
 * \date    Mar 2007
 */

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <netdb.h>
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"
#include "../headers/pattern_inspection.h"


extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*errors;
extern	t_benchmark	bench;
extern	t_analyze	analyze;
extern 	t_option	option;
extern t_error		**errors_list;

int cmp_error_sever(const void *a, const void *b);
int error_display_plain(t_error *e, _u8 type);
int error_display_xml(t_error *e, _u8 type);


void error_output(_u8 type, _s32 limit)
{
	_u32 		 i, max = 0, count = 0;
	qsort(errors_list, analyze.error_stated, sizeof(t_error*), cmp_error_sever);
	if(type == TYPE_ERROR)
	{	
		if (option.xml)
			out("\n<errors>\n");
		if (analyze.error > 0 && analyze.error < analyze.error_stated)
			max = analyze.error;
		else
			max = analyze.error_stated;
	} else if (type == TYPE_EVENT)
	{
		if (option.xml)
			out("\n<events>\n");
		if (analyze.event > 0 && analyze.event < analyze.error_stated)
			max = analyze.event;
		else
			max = analyze.error_stated;
	}
	
	//can't do it backward due to sorting
	for(i = 0; i < analyze.error_stated; i++)
	{
		//we need to use count because session can be either event or error
		if (errors_list[i])
		{
			if(option.xml)
				count +=  error_display_xml(errors_list[i], type);
			else
				count += error_display_plain(errors_list[i], type);
		}
		if (count == max) break;
	}
	
	if(type == TYPE_ERROR)
	{	
		if (option.xml)
			out("\n</errors>\n");
	} else if (type == TYPE_EVENT)
	{
		if (option.xml)
			out("\n</events>\n");
	}
}

/*!
 * used to display error or events detailed information
 * @param e the structure to display
 * @param type the type of display wanted : error or event
 * @see error_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
*/
int error_display_plain(t_error *e, _u8 type)
{
	struct 	in_addr		ip;
	assert(e);
	assert(e->ip);
	assert(e->type);
	assert(e->layer);
	assert(e->name);
	
	if(e->type != type)
		return 0;
	ip.s_addr = e->ip;
	
	if (type == TYPE_EVENT)
		out("[Event] S:");
	else
		out("[Error] S:");
	
	//severity
	     if (e->severity >= 8) out("%s%d%s", cl.red, e->severity, cl.clr);
	else if (e->severity >= 5) out("%s%d%s", cl.yel, e->severity, cl.clr);
	else if (e->severity > 0) out("%s%d%s", cl.gre, e->severity, cl.clr);
	
	//layer
	     if (e->layer == 4) out("L:%s%d%s", cl.pur, e->layer, cl.clr);
	else if (e->layer == 3) out("L:%s%d%s", cl.yel, e->layer, cl.clr);
	else if (e->layer == 2) out("L:%s%d%s", cl.cya, e->layer, cl.clr);
	else if (e->layer == 1) out("L:%s%d%s", cl.blu, e->layer, cl.clr);
	
	out(" %s", inet_ntoa(ip));
	
	out(": %s%s%s", cl.yel, e->name, cl.clr);	
	
	if (e->group[0] != '\0')
		out(" (%s%s%s)", cl.pur, e->group, cl.clr);
	
	if (e->target[0] != '\0')
		out(" Target:%s%s%s", cl.cya, e->target, cl.clr);
	
	if (e->class_shortname[0] != '\0')
		out(" Class:%s%s%s", cl.clr, e->class_shortname, cl.clr);
	
	if(e->class_details[0] != '\0')
		out("%s%s%s", cl.clr, e->class_details, cl.clr);
	
	out(" nbseen:%s%d%s", cl.gre, e->frequency, cl.clr);

	out("\n");

	
	//snprintf(sbuff,15,"%s", inet_ntoa(src));
	//snprintf(obuff,512,"%d/%d\t %s\t %s:%s %s (%s)\n",e->layer, e->severity, sbuff, e->group, e->name, e->details, e->target);
	//out(obuff);
	return 1;
}

/*!
 * used to display error or events detailed information in xml
 * @param e the structure to display
 * @param type the type of display wanted : error or event
 * @see error_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
*/
int error_display_xml(t_error *e, _u8 type)
{
	out("\t<error id=\"%lld\"  layer=\"%d\"  type=\"%d\"  crc=\"%lld\"  class_shortname=\"%s\"  severity=\"%d\"  class_details=\"%s\"  name=\"%s\"  group=\"%s\"  details=\"%s\"  target=\"%s\"  nature=\"%d\"  session_id=\"%lld\"  host_id=\"%lld\"  ip=\"%d\"  frequency=\"%d\"  first_time=\"%lld\"  first_time_usec=\"%lld\"  last_time=\"%lld\"  last_time_usec=\"%lld\" ></error>\n",
	e->id, e->layer, e->type, e->crc, e->class_shortname, e->severity, e->class_details, e->name, e->group, e->details, e->target, e->nature, e->session_id, e->host_id, e->ip, e->frequency, e->first_time, e->first_time_usec, e->last_time, e->last_time_usec);
	return 1;
}


/*!
 * used to sort error by severity
 * @param a error structure 1
 * @param b error structure 2
 * @see user2user_output()
 * \version 1
 * \date   Mar 2007
 * \author Elie	
 */

int cmp_error_sever(const void *a, const void *b)
{
	t_error *e1 = *(t_error **) (a);
	t_error *e2 = *(t_error **) (b);
	
	if(e1->severity > e2->severity) 	return 1;
	if(e1->layer > e2->layer) 		return 1;
	if(e1->frequency > e2->frequency) 	return 1;
	
	return 2;
}
