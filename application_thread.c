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
 *	\file application_thread.c
 *	\brief 6th thread: used for application layer analysis
 *
 *	This file containt the entry point for signatures matching
 *	\author  Elie
 *	\version 1.0
 *	\date    2007
 */

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"

extern 	t_option 	option;
extern 	t_mutex		mutex;
extern	t_analyze	analyze;
extern	t_tuning	tuning;


//function launched by the thread
void application_function() {
	t_pkt *p;
	
  	while (mutex.thread_sync < THREAD_START_AP)
		  usleep(1);
	
	while(1)
	{
		if(fifo_need_swap_traf())
    		{	
			//locking it's own thread
			pthread_mutex_lock(&mutex.processover);
			//getting data Lock the paser
			pthread_mutex_lock(&mutex.tra2app);
			fifo_swap_traf();
			pthread_mutex_unlock(&mutex.tra2app); 
			
			///!\todo: add layer7 decoding based on TIE
		
			while((p = fifo_next_app()) != NULL)
			{
					//patten analysis ?
				if(tuning.usepattern && analyze.advanced != 0)
				{
					//see traffic_pattern_function.c
					if  (p && p->s)
						analyze_traffic_pattern(p->s, p);
				}
			
				
			}
			//freeing queue
			fifo_free_app();
			pthread_mutex_unlock(&mutex.processover);
		}
		usleep(1000);
		sched_yield();
			
		if (mutex.thread_sync_stop == THREAD_STOP_AP  && fifo_size_traf() == 0)
			 return;
	}
}
