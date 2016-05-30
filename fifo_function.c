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
 *	\file fifo_function.c
 *	\brief functions used for handling packets fifo between thread
 *
 *	This file contains every functions related to fifo handeling. This is also where the 
 *	fifo policy is applied
 *	\author  Elie
 *	\version 1.0
 *	\date   Feb 2007
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
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"

extern t_option			option;
extern t_analyze		analyze;
extern t_tuning			tuning;
extern t_mutex			mutex;
extern t_benchmark		bench;
t_fifo_pkt			fifo;///!<packets fifo

//internal function prototype
t_pkt *fifo_new_packet(char *buf, unsigned int len, _u64 num, long time, long time_usec);



//Underlaying generic function

/*!
 * swap two list of packet
 * @param l1 first pkt list
 * @param ll1 first pkt last list;
 * @param l2 second pkt list;
 * @param ll2 second pkt last list2;
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
void fifo_swap(t_pkt **l1, t_pkt **ll1, t_pkt **l2, t_pkt **ll2) {
	*l2 	= *l1;
	*ll2	= *ll1;
	*l1 	= NULL;
	*ll1	= NULL;
}

/*!
 * add a pakcet to a fifo
 * @param l the fifo
 * @param ll the fifo last packet
 * @param pkt the packet
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
void fifo_add(t_pkt **l, t_pkt **ll, char *buf, unsigned int len, _u64 num, long t, long time_usec)
{	
	if (!(*l))
	{
		*l = fifo_new_packet(buf, len, num, t, time_usec);
		*ll = *l;
	} else {
		 
		(*ll)->next = fifo_new_packet(buf, len, num, t, time_usec);
		*ll = (*ll)->next;
	}
	bench.len += len;
	//printf("%lld\n", bench.len);
	assert(*l != NULL);
}

/*!
 * create a new packet structure
 * @param buf packet content
 * @param len packet len according to pcap
 * @param num packet unique number 
 * @param time pcap time of capture in sec
 * @param time_usec pcap time of capture in usec
 * @return a packet structure
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
 
t_pkt *fifo_new_packet(char *buf, unsigned int len, _u64 num, long t, long time_usec)
{
	t_pkt 	*tmp;
	//be sure it's ok
	assert(len > 0);
	tmp = xmalloc(sizeof(t_pkt));
	bzero(tmp, sizeof(t_pkt));
	//setting packet num
	tmp->id = num;
	//tmp->pkt_num = (int)num;
	//cpy pcap time of capture
	tmp->time_capture = (_s64) t;
	tmp->time_capture_usec = (_s64) time_usec;
	//cpy pcap data
	tmp->buf = (char *)xmalloc(sizeof(char)*(len + 1));
	memcpy(tmp->buf, buf, len);
	//make sur packet is null terminated (can save a lot of trouble)
	tmp->buf[len] = '\0';
	//len of data 
	tmp->len = len;
	//marking the packet has not decoded yet
	tmp->pkt_proto = NOTDECODED;
	return tmp;
}

/*!
 * destroy a packet
 * @param p the packet  
 * @return NULL
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * \attention Most structure are simple pointer on the p->buf you just free the buf..
 * \todo
 */

void	fifo_free_packet(t_pkt *p)
{
	free(p->buf);
	p->buf = NULL;
	if (p->tcp_opt)
		free(p->tcp_opt);
	free(p);
	p = NULL;
}

/*!
 * destroy a fifo
 * @param lst the fifo  
 * @return NULL
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 * \attention
 * \todo
 */
 
int fifo_free(t_pkt *lst)
{
	t_pkt	*tmp;
	while(lst)
	{
		tmp = lst;
		lst = lst->next;
		fifo_free_packet(tmp);
		bench.freepkt++;
	}
	return 0;
}

//thread specific one


//##### COLLECTOR ######

/*!
 * force fifo flush when there is no more packet in the pcap file
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_col_readover()
{
	fifo.col_size = -1;
}


/*!
 * add to the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_add_col(char *buf, unsigned int len, long t, long time_usec)
{
	assert(len > 0);
	assert(t > 0);
	bench.nbpkt++;
	fifo_add(&fifo.col, &fifo.col_last, buf, len, bench.nbpkt, t, time_usec);
	//increment after to avoid possible race condition
	fifo.col_size++;
	fifo.col_last_time = time(NULL);
	
	assert(fifo.col != NULL);
	//display if needed
	if(option.debug == 4)
		printf("Collector Adding packet %lld to fifo in position %lld\n", bench.nbpkt, fifo.col_size);
}



/*!
 * indicate if swaping is required between
 * \return 1 for yes 0 for no
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
 
int fifo_need_swap_col()
{
	//something to swap ?
	if(fifo.col_size == 0)
		return 0;


	//decoder ready ? if not wait until fifo has been transfered otherwise we loose pkt
	if(fifo.dec != NULL  || fifo.dec_next != NULL)
		return 0;
	
	assert(fifo.col->id == fifo.dec_last_pkt + 1);
	
	//max size reached ?
	if(fifo.col_size >= tuning.fifo_size)
		return 1;
	//max time reached ?
	if((fifo.col_last_time != 0) && ((time(NULL) - fifo.col_last_time) >= tuning.fifo_max_time))
		return 1;
		//readover
	if(fifo.col_size == -1)
		return 1;
	
	return 0;
}


/*!
 * indicate if more packet can be added to the fifo 
 * \return 1 for yes 0 for no
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */

int fifo_col_ready()
{
	if(fifo.col_size >= tuning.fifo_size)
		return 0;
	return 1;
}

/*!
 * swap the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_swap_col()
{
	if(option.debug == 1)
		printf("Swaping collector fifo size %lld\n", fifo.col_size);
	
	assert(fifo.col_size != 0);
	fifo_swap(&fifo.col, &fifo.col_last, &fifo.dec, &fifo.dec_last);
	assert(fifo.dec != NULL);
	//reseting
	fifo.dec_size = fifo.col_size;
	fifo.dec_next = fifo.dec;

	fifo.col_size = 0;
	fifo.col_next = fifo.col;
	fifo.col_last_time = time(NULL);
}

/*!
 * return  fifo size
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
int fifo_size_col() {
	return fifo.col_size;
}

//##### decoder ######



/*!
 * get next packet of the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
t_pkt *fifo_next_dec()
{
	t_pkt 	*p;
	
	
	assert((fifo.dec == NULL && fifo.dec_last == NULL) || (fifo.dec != NULL && fifo.dec_last != NULL));
	
	if(fifo.dec == NULL)
		return NULL;
	p = fifo.dec_next;
	//fifo.dec_next == NULL for the last element
	if(fifo.dec_next != NULL)
	{
		assert(fifo.dec_next->id == ++fifo.dec_last_pkt);
		fifo.dec_next = fifo.dec_next->next;
		if(option.debug == 5)
			printf("Decoder procession pkt %lld\n", p->id);
	}
	return p;
}



/*!
 * indicate if swaping is required between par and stat
 * \return 1 for yes 0 for no
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
 
int fifo_need_swap_dec()
{
	//something to do ?
	if(fifo.dec_size == 0) { 
		return 0;
	}
	//are the statefull fifo ready ?
	if(fifo.stat != NULL  || fifo.stat_next != NULL) {
		return 0;
	}
	
	//fifo proceeded and not empty
	if(fifo.dec_next == NULL && fifo.dec != NULL)
		return 1;
	return 0;
}


/*!
 * swap the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_swap_dec()
{
 	if(option.debug == 1)
		printf("Swaping Decoder fifo size %lld\n", fifo.dec_size);
	
	fifo_swap(&fifo.dec, &fifo.dec_last, &fifo.stat, &fifo.stat_last);
	assert(fifo.stat != NULL);
	//reseting
	fifo.stat_size 	= fifo.dec_size;
	fifo.stat_next 	= fifo.stat;
	
	fifo.dec_size 	= 0;
	fifo.dec_next 	= fifo.dec;

}

/*!
 * return  fifo size
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */


int fifo_size_dec() {
	return fifo.dec_size;
}



//#### STATEFULL


/*!
 * indicate if swaping is required between sta and tra
 * \return 1 for yes 0 for no
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
 
int fifo_need_swap_stat()
{
	//something to do ?
	if(fifo.stat_size == 0)
		return 0;
	//are the statefull fifo ready ?
	if(fifo.traf != NULL || fifo.traf_next != NULL)
		return 0;
	//fifo proceeded and not empty
	if(fifo.stat_next == NULL && fifo.stat != NULL)
		return 1;
	return 0;
}


/*!
 * swap the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_swap_stat()
{
 	if(option.debug == 1)
		printf("Swaping Statefull fifo size %lld\n", fifo.stat_size);
	
	fifo_swap(&fifo.stat, &fifo.stat_last, &fifo.traf, &fifo.traf_last);
	assert(fifo.traf != NULL);
	//reseting
	fifo.traf_size 	= fifo.stat_size;
	fifo.traf_next 	= fifo.traf;
	
	fifo.stat_size 	= 0;
	fifo.stat_next 	= fifo.stat;

}

/*!
 * get next packet of the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
t_pkt *fifo_next_stat()
{
	t_pkt 	*p;
	
	
	assert((fifo.stat == NULL && fifo.stat_last == NULL) || (fifo.stat != NULL && fifo.stat_last != NULL));
	
	if(fifo.stat == NULL)
		return NULL;
	p = fifo.stat_next;
	//fifo.dec_next == NULL for the last element
	if(fifo.stat_next != NULL)
	{
		assert(fifo.stat_next->id == ++fifo.stat_last_pkt);
		fifo.stat_next = fifo.stat_next->next;
		if(option.debug == 6)
			printf("Statefull procession pkt %lld\n", p->id);
	}
	return p;
}

/*!
 * return  fifo size
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */


int fifo_size_stat() {
	return fifo.stat_size;
}

//#### Traffic

/*!
 * indicate if swaping is required between traf and app
 * \return 1 for yes 0 for no
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
 
int fifo_need_swap_traf()
{
	//something to do ?
	if(fifo.traf_size == 0)
		return 0;
	//are the traf fifo ready ?
	if(fifo.app != NULL || fifo.app_next != NULL)
		return 0;
	//fifo proceeded and not empty
	if(fifo.traf_next == NULL && fifo.traf != NULL)
		return 1;
	return 0;
}


/*!
 * swap the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
void fifo_swap_traf()
{
 	if(option.debug == 1)
		printf("Swaping traffic fifo size %lld\n", fifo.traf_size);
	
	fifo_swap(&fifo.traf, &fifo.traf_last, &fifo.app, &fifo.app_last);
	assert(fifo.app != NULL);
	//reseting
	fifo.app_size 	= fifo.traf_size;
	fifo.app_next 	= fifo.app;
	
	fifo.traf_size 	= 0;
	fifo.traf_next 	= fifo.traf;

}


/*!
 * get next packet of the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
t_pkt *fifo_next_traf()
{
	t_pkt 	*p;
	
	
	assert((fifo.traf == NULL && fifo.traf_last == NULL) || (fifo.traf != NULL && fifo.traf_last != NULL));
	
	if(fifo.traf == NULL)
		return NULL;
	p = fifo.traf_next;
	//fifo.dec_next == NULL for the last element
	if(fifo.traf_next != NULL)
	{
		assert(fifo.traf_next->id == ++fifo.traf_last_pkt);
		fifo.traf_next = fifo.traf_next->next;
		if(option.debug == 7)
			printf("Traffic thread process pkt %lld\n", p->id);
	}
	return p;
}

/*!
 * return  fifo size
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */


int fifo_size_traf() {
	return fifo.traf_size;
}

//#### APPLICATION

/*!
 * get next packet of the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */
t_pkt *fifo_next_app()
{
	t_pkt 	*p;
	
	
	assert((fifo.app == NULL && fifo.app_last == NULL) || (fifo.app != NULL && fifo.app_last != NULL));
	
	if(fifo.app == NULL)
		return NULL;
	p = fifo.app_next;
	//fifo.dec_next == NULL for the last element
	if(fifo.app_next != NULL)
	{
		assert(fifo.app_next->id == ++fifo.app_last_pkt);
		fifo.app_next = fifo.app_next->next;
		if(option.debug == 7)
			printf("Application thread process pkt %lld\n", p->id);
	}
	return p;
}

/*!
 * free all the packet in the fifo
 * \version 1.0
 * \date   Feb 2007
 * \author Elie
 */

void fifo_free_app()
{
	if(option.debug == 7)
			printf("Application thread free fifo\n");
	fifo_free(fifo.app);
	fifo.app_size = 0;
	fifo.app = NULL;
	fifo.app_next = NULL;
	fifo.app_last = NULL;
}
