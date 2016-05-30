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
 *	\file output_thread.c
 *	\brief 6th thread: used to output information.
 *
 *	This file/thread is used to output the data of the analyzer. it's design to be asynchronous.
 *	\author  Elie
 *	\version 3.0
 *	\date    2006
 */
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
#include "headers/pattern_inspection.h"

#define		BUF_SIZE	1024

extern 	t_option 			option;
extern 	t_mutex			mutex;
extern	int				readstatus;
extern	t_analyze			analyze;
extern	t_term_color		cl;
extern	t_benchmark		bench;


void readwait()
{
  //reading a file waiting for output
  if(option.fname != NULL)
  {
	if(option.debug == 2)
		printf("trying to lock readover\n");
	//finish to read packets ?
	pthread_mutex_lock(&mutex.readover);
      	if(option.debug == 2)
      		printf("readover locked\n");
  } else {
    //live capture handling time between output
    sleep(option.intervall);
  }
}

//function call by the thread
void output_function (void)
{
	 _s32  t;
  	t = time(NULL);
	while(mutex.thread_sync < THREAD_START_OUT)
		usleep(1);
  	while(1)
  	{
    	//waiting for ouput
    	readwait();
	
	//Locking process queue
	pthread_mutex_lock(&mutex.processover);
	
	//pthread_mutex_lock(&mutex.app2out);
	//cleaning session

	//pthread_mutex_unlock(&mutex.app2out);
	
	
	//create of table session
	if(analyze.session || analyze.protocol)
		pthread_mutex_lock(&mutex.hashsession);
		session_make_array();
		pthread_mutex_unlock(&mutex.hashsession);
	//Host sorting
	if(analyze.host)
		pthread_mutex_lock(&mutex.hashhost);
		host_sorting(); ///\todo rename it to proper function
		pthread_mutex_unlock(&mutex.hashhost);
	//protocol stats
	if(analyze.protocol)
		protocol_stating();
	//software 
	if (analyze.software)
		software_sorting();
	//error sorting
	if(analyze.error != 0 || analyze.event != 0)
		error_sorting();
	//user
	if (analyze.user)
	{
		user_sorting();
		user2user_sorting();
	}
		
	
	if(option.xml)
		/*! report_id is used for db update because session uniq id is relative to the execution*/
		out("<?xml version=\"1.0\"?>\n<netanalyzer report_id=\"%lld\">\n", bench.startime); 
	else 
		printf("Analyze result (intervall : %d sec)\n", option.intervall); 
	
	if(analyze.session)
		session_output(SESS_DISP_ALL,1);
	
	if(analyze.host && option.fancy != 2)
		host_output(1,1);
	
	if(analyze.protocol && option.fancy != 2)
		protocol_output(1,1);
	
	if(analyze.software)
		software_output(1,1);
	
	if(analyze.user && option.fancy != 2)
	{
		user_output(1, 1);
		user2user_output(1,1);
	}
	
	if(analyze.error && option.fancy != 2)
		error_output(TYPE_ERROR, 1);
	
	if(analyze.event && option.fancy != 2)
		error_output(TYPE_EVENT, 1);
	
	if(option.xml)
		out("%s\n</netanalyzer>\n",cl.clr);	

	 if(option.benchmark)
	{
		  benchmark(t);
		  t = time(NULL);
  	}
	//cleaning
	if(analyze.session || analyze.protocol)
	{
		pthread_mutex_lock(&mutex.hashsession);
		session_clean();
		pthread_mutex_unlock(&mutex.hashsession);

	}
	//cleaning host
	if(analyze.host)
	{
		pthread_mutex_lock(&mutex.hashhost);
		host_clean();
		pthread_mutex_unlock(&mutex.hashhost);
	}
	
	//cleanning protocol no mutex needed : only computed here
	if(analyze.protocol)
	{
		protocol_clean();
	}
	
	if(analyze.user && option.fancy != 2)
	{
		pthread_mutex_lock(&mutex.hashuser);
		user_clean();
		pthread_mutex_unlock(&mutex.hashuser);
		
		pthread_mutex_lock(&mutex.hashuser2user);
		user2user_clean();
		pthread_mutex_unlock(&mutex.hashuser2user);

	}
	
	if(analyze.error || analyze.event)
	{
		pthread_mutex_lock(&mutex.hasherror);
		error_clean();
		pthread_mutex_unlock(&mutex.hasherror);
	}

	
	//Locking process queue
	pthread_mutex_unlock(&mutex.processover);
	//time to die
   	 if (mutex.thread_sync_stop == THREAD_STOP_OUT)
    	{
      		return;
    	}
  }
}
