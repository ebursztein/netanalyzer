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
 *	\file parser_thread.c
 *	\brief 2nd thread: used to decode and analyze layers 1-3.
 *
 *	This file is used for decoding and analyzing low level protocols and prepare packet for traffic inspection.
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
#include <unistd.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/sanity.h"

extern 	t_option 	option;
extern	t_analyze	analyze;
extern 	t_mutex		mutex;
extern	int		readedpacket;
extern	t_pkt		*first;
extern	t_pkt		*last;
t_pkt			*first_decoded = NULL;
t_pkt			*last_decoded = NULL;
void decoder_function()
{
	t_pkt *p;

  //sync thread before starting
  while (mutex.thread_sync < THREAD_START_DEC) {
	usleep(1);
	if(option.debug == 2)
	 printf("parser wait\n");
  }
  while(1) 
  {
    //be sure that there is data and previous data are in the hand of analyzer
    //if(first != NULL && first_decoded == NULL)
    if(fifo_need_swap_col() != 0)
    {
	// Lock the mutex
	pthread_mutex_lock(&mutex.col2dec);
	pthread_mutex_lock(&mutex.dec2sta);
	fifo_swap_col();
	pthread_mutex_unlock(&mutex.col2dec);

	while((p = fifo_next_dec()) != NULL)
	{
		///\todo analyze wifi (separate ssid)
		//last_decoded = decode_ether(last_decoded);
		decode_ether(p);
		//if (option.debug == 1)
		//	printf("PARSER:\t\tpkt %d\n", last_decoded->pkt_num);
		///!\todo deeper level3 analysis: 
		//analyze(last_analyzed);
		//analyze checksum 
		//analyze passive os fingerprint (bayesian) need to patch a lot of stuff:) server, host, )
		//analyze nat
		//analyze firewall
		//analyze mtu
		//analyze tos
		//isn analysis (randomness -> add isn to xml)
		//port randomness ?(need to be in gui )
		//sanity
		///!\todo fixme sanity analysis
		if (analyze.sanity)
		{
			//sanity_print_pkt(last_decoded);
			;
		}
		//last_decoded = last_decoded->next;
	
	}
	pthread_mutex_unlock(&mutex.dec2sta);
	//printf("unlock mutex.par2ana\n");
    }
    	usleep(1000);
	sched_yield();
    //do we have finish ?
    if (mutex.thread_sync_stop == THREAD_STOP_DEC && fifo_size_col() == 0)
  	return;
  }
}
