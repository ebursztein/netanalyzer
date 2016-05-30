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
 *	\file traffic_thread.c
 *	\brief 4th thread: used for traffic analysis such as phase detection
 *
 *	This file include profile, phase, scoring and so one but not application layer analysis!
 *	\author  Elie
 *	\version 3.0
 *	\date    2006
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

extern 	t_option 	option;
extern 	t_mutex		mutex;
extern	int		readstatus;
extern	int		readedpacket;
extern	t_analyze	analyze;

extern	t_session		**sessions_list;
extern	t_host			**hosts_list;
extern  t_tabproto		protocols_list;

//function launched by the thread  
void traffic_function(void) {
	t_pkt	*p;
	
	while (mutex.thread_sync < THREAD_START_TRA)
	{
		usleep(1);
		if(option.debug == 2)
			printf("traffic wait\n");	
	}
	while(1)
	{
		if(fifo_need_swap_stat())
    		{
			//getting data Lock the paser
			pthread_mutex_lock(&mutex.sta2tra);
			pthread_mutex_lock(&mutex.tra2app);
			fifo_swap_stat();
			pthread_mutex_unlock(&mutex.sta2tra); 
			
			///!\todo: add layer7 decoding based on TIE
		
			while((p = fifo_next_traf()) != NULL)
			{
				
				///ICMP mtu
				if (p->pkt_proto == ICMP)
					traffic_mtu_packet(p);
				///traffic analysis 
				//if(p->pkt_proto >= UDP)
				if  (p && p->s)
					traffic_analyze(p->s, p);
				///!\todo check gateway detection technique				
				//gw extraction
				//gateway_detect();
			}
			pthread_mutex_unlock(&mutex.tra2app);
    		}
		usleep(1000);
		sched_yield();	
		//time to exit
		if (mutex.thread_sync_stop == THREAD_STOP_TRA  && fifo_size_stat() == 0)
                    return;
	}
}
