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
 * \file user.c
 * \brief functions used for user ouput in the output thread
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

#define USER_STANDALONE 1
#define USER_SESSION	2

extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*users;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_user		**users_list;

int cmp_user_ip(const void *a, const void *b);

void user_display_plain(t_user *u, _u8 type);
void user_display_xml(t_user *u, _u8 type);


void user_output(_u8 type, _s32 limit)
{


	_u32 		 i, max;
	qsort(users_list, users->entrycount, sizeof(t_user*), cmp_user_ip);
	if (option.xml)
		out("<users>");
	else
		out("### Users analyze\n\n");
	//limiting output if requested
	if (analyze.user > 0 && analyze.user < analyze.user_stated)
		max = analyze.user;
	else
		max = analyze.user_stated;
	//can't do it backward due to sorting
	if (max == 0)
	 	return;
	for(i = 0;i < max; i++)
	{
		if (users_list[i]) {
			if(option.xml)
				user_display_xml(users_list[i], USER_STANDALONE);
			else
				user_display_plain(users_list[i], USER_STANDALONE);
		}
	}
	if(option.xml)
		out("</users>");
}




/*!
 * used to display user information for both standlone view and session one
 * @param u the user structure
 * @param type standalone or session view
 * @see session_output()
 * \version 1.0
 * \date   Mar  2007
 * \author Elie	
*/
void user_display_plain(t_user *u, _u8 type)
{
	struct 	in_addr		ip;
	assert(u);
	assert(u->ip);
	ip.s_addr = u->ip;
	
	out("[User]");
	
	out(": %s%s%s", cl.yel, u->login, cl.clr);
	
	if(type == USER_STANDALONE)
	{
		if (u->ip);
			out("@%s%s%s", cl.cya, inet_ntoa(ip), cl.clr);
	}
	
	if (u->hostname[0] != '\0')
		out(" (%s%s%s)", cl.cya, u->hostname, cl.clr);
	
	if (option.debug == 666 && u->pass)
		out(":%s", cl.red, u->pass, cl.clr);
	
	if (u->algorithm[0] != '\0')
		out(" algo:%s%s%s", cl.gre, u->algorithm, cl.clr);
	     
	     if (u->pass_strength >= 8) out(" Password Strength :%sStrong (%d)%s", cl.gre, u->pass_strength, cl.clr);
	else if (u->pass_strength >= 5) out(" Password Strength :%sOk (%d)%s", cl.yel, u->pass_strength, cl.clr);
	else if (u->pass_strength >= 1) out(" Password Strength :%sWeak (%d)%s", cl.red, u->pass_strength, cl.clr);
	
	if (u->familly[0] != '\0')
		out(" familly:%s%s%s", cl.pur, u->familly, cl.clr);
	
	if (u->origin[0] != '\0')
		out(" Origin:%s%s%s", cl.cya, u->origin, cl.clr);
	
	if (u->nature == RELATION_DIRECT)
		out("%sActive user%s",cl.yel, cl.clr);
	else
		out("%sIndirect user%s",cl.yel, cl.clr);
	
	if (u->additionnal[0] != '\0')
		out(" Type:%s%s%s", cl.cya, u->additionnal, cl.clr);
	
	out(" nbseen:%s%d%s", cl.gre, u->frequency, cl.clr);
	out("\n");
	
}


/*!
 * used into the session output to print user information
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
 */
void user_session_display_plain(t_session *s)
{
	t_user	*u;
	u = s->user;
	while(u)
	{
		user_display_plain(u, USER_SESSION);
		u = u->next;
	}
}


/*!
 * used into the session output to print user information in xml
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
 */
void user_session_display_xml(t_session *s)
{
	t_user	*u;
	u = s->user;
	if (u == NULL)
		return;
	out("\t<users>");
	while(u)
	{
		user_display_xml(u, USER_SESSION);
		u = u->next;
	}
	out("\t</users>");
}


/*!
 * used to display in XML user information for both standlone view and session one
 * @param u the user structure
 * @param type standalone or session view
 * @see session_output()
 * \version 0.0
 * \date   Mar  2007
 * \author Elie	
*/
void user_display_xml(t_user *u, _u8 type)
{
	if(type == USER_SESSION)
		out("\t");
	out("\t<user id=\"%lld\"  crc=\"%lld\"  protocol=\"%s\"  familly=\"%s\"  login=\"%s\"  pass=\"%s\"  algorithm=\"%s\"  additionnal=\"%s\"  origin=\"%s\"  nature=\"%d\"  hostname=\"%s\"  ip=\"%d\"  host_id=\"%lld\"  last_time=\"%lld\"  last_time_usec=\"%lld\"  start_time=\"%lld\"  start_time_usec=\"%lld\"  frequency=\"%d\"  pass_strength=\"%d\" ></user>\n",
	u->id, u->crc, u->protocol, u->familly, u->login, u->pass, u->algorithm, u->additionnal, u->origin, u->nature, u->hostname, u->ip, u->host_id, u->last_time, u->last_time_usec, u->start_time, u->start_time_usec, u->frequency, u->pass_strength);

}


/*!
 * sort user by ip
 * @param s the session
 * @see session_output()
 * \version 1
 * \date   Feb 2007
 * \author Elie	
 * \todo move this to a generic output that can be use for session and mapping 
 */

int cmp_user_ip(const void *a, const void *b)
{
	t_user *u1 = *(t_user **) (a);
	t_user *u2 = *(t_user **) (b);
	//sorting ip and then by num of conn
	if(u1->ip > u2->ip)
		return -1;
	else if(u1->ip < u2->ip)
		return 1;
	else if(u1->nature > u2->nature)
		return -1;
	return 1;
}

