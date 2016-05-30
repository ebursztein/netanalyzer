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
 *	\file statefull_analyszer.c
 *	\brief 3rd thread: used for statefull analysis
 *
 *	This file containt the entry point to the session statefull inspection and host analysis.
 *	It is probably one of the heaviest task perform by the analyzer so be sur to not add to much things here
 *	\author  Elie
 *	\version 4.1
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


//function launched by the thread
void stateful_function() {
	t_pkt 	*p;
	_s32	ret;
  	while (mutex.thread_sync < THREAD_START_STA)
		  usleep(1);
	while(1)
	{
		
		if(fifo_need_swap_dec())
    		{
			
			//getting data Lock the paser
			pthread_mutex_lock(&mutex.dec2sta);
			pthread_mutex_lock(&mutex.sta2tra);
			fifo_swap_dec();
			pthread_mutex_unlock(&mutex.dec2sta); 
			
			while((p = fifo_next_stat()) != NULL)
			{
				//TCPdump analysis
				//session analysis (mandatory statefull power) analyze only correct packet
				///!\todo verify syn payload and session port != 0 et port src != port dst , ip src != ip dst
				ret = analyze_session(p);
				if(ret >0)
					analyze_host(p, ret); /*!mandatory because we use it in relation between session (host_id) */
			}
			pthread_mutex_unlock(&mutex.sta2tra);
    		}
		usleep(1000);
		sched_yield();
    		//file reading is over
		if (mutex.thread_sync_stop == THREAD_STOP_STA  && fifo_size_dec() == 0)
  	   		 return;
  	}
}
