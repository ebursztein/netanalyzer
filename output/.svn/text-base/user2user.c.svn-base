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
 * \file user2user.c
 * \brief functions used for user relation ouput in the output thread
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

#define U2U_STANDALONE 	1
#define U2U_SESSION	2


extern	t_term_color	cl;
extern 	_u32 		primes[];
extern	t_hash		*users2users;
extern	t_option	option;
extern	t_analyze	analyze;
extern	t_user_to_user	**users2users_list;

int cmp_user2user_freq(const void *a, const void *b);

void user2user_display_plain(t_user_to_user *u, _u8 type);
void user2user_display_xml(t_user_to_user *u, _u8 type);


void user2user_output(_u8 type, _s32 limit)
{


	_u32 		 i, max;
	qsort(users2users_list, users2users->entrycount, sizeof(t_user*), cmp_user2user_freq);
	if (option.xml)
		out("<userRelations>");
	else
		out("#### Users Relation report\n\n");
	//limiting output if requested
	if (analyze.user > 0 && analyze.user < analyze.user2user_stated)
		max = analyze.user;
	else
		max = analyze.user2user_stated;
	//can't do it backward due to sorting
	if (max == 0)
	 	return;
	for(i = 0;i < max; i++)
	{
		if (users2users_list[i])
		{
			if(option.xml)
				user2user_display_xml(users2users_list[i], U2U_STANDALONE);
			else
				user2user_display_plain(users2users_list[i], U2U_STANDALONE);
		}
	}
	if(option.xml)
		out("</userRelations>");
}


/*!
 * used into the session output  user2user information in session
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
 */
void 	user2user_session_display_plain(t_session *s)
{
	t_user_to_user	*u;
	u = s->user2user;
	while(u)
	{
		user2user_display_plain(u, U2U_SESSION);
		u = u->next;
	}
}


/*!
 * used into the session output  user2user information in session
 * @param s the session
 * @see session_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
 */
void 	user2user_session_display_xml(t_session *s)
{
	t_user_to_user	*u;
	u = s->user2user;
	if (u == NULL)
		return;
	out("\t<UserRelation>");
	
	while(u)
	{
		user2user_display_xml(u, U2U_SESSION);
		u = u->next;
	}
	out("\t</UserRelation>");
}


/*!
 * used to display user relation information
 * @param u the structure to display
 * @see user2user_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
*/
void user2user_display_plain(t_user_to_user *u, _u8 type)
{
	assert(u);
	assert(u->sender);
	assert(u->receiver);
	
	out("[User Relation]");
	
	out(": %s%s%s->%s%s%s", cl.yel, u->sender, cl.clr, cl.yel, u->sender, cl.clr);
	
	
	if (u->protocol[0] != '\0')
		out(" (%s%s%s)", cl.cya, u->protocol, cl.clr);
	
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
 * used to display user relation information in xml
 * @param u the structure to display
 * @see user2user_output()
 * \version 1.1
 * \date   Mar 2007
 * \author Elie	
*/
void user2user_display_xml(t_user_to_user *u, _u8 type) {
	if(type == U2U_SESSION)
		out("\n");
	out("\t<user_to_user host_id_src=\"%lld\"  host_id_dst=\"%lld\"  id=\"%lld\"  crc=\"%lld\"  ip=\"%d\"  sender=\"%s\"  receiver=\"%s\"  protocol=\"%s\"  familly=\"%s\"  additionnal=\"%s\"  origin=\"%s\"  nature=\"%d\"  first_time=\"%lld\"  first_time_usec=\"%lld\"  last_time=\"%lld\"  last_time_usec=\"%lld\"  frequency=\"%d\" ></user_to_user>\n",
	u->host_id_src, u->host_id_dst, u->id, u->crc, u->ip, u->sender, u->receiver, u->protocol, u->familly, u->additionnal, u->origin, u->nature, u->first_time, u->first_time_usec, u->last_time, u->last_time_usec, u->frequency); 
}

/*!
 * used to sort user relation by frequency
 * @param a user2user structure 1
 * @param b user2user structure 2
 * @see user2user_output()
 * \version 1
 * \date   Mar 2007
 * \author Elie	
 */
int cmp_user2user_freq(const void *a, const void *b)
{
	t_user *u1 = *(t_user **) (a);
	t_user *u2 = *(t_user **) (b);
	//sorting ip and then by num of conn
	if(u1->frequency > u2->frequency)
		return -1;
	return 1;
}


