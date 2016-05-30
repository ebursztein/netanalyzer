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
 *	\file bench.c
 *	\brief bench functions.
 *
 *	Regroup the functions used to profile netanalyzer and performs various benchmarks
 *	\author  Elie
 *	\version 1.1
 *	\date    Mar 2007
 * 	\todo FIXME:need a signal handler for live statistiques
 */

#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "headers/structure.h"
#include "headers/function.h"
#include "headers/types.h"
#include "headers/traffic_inspection.h"
#include "headers/pattern_inspection.h"

extern t_option			option;
extern t_analyze		analyze;
extern t_tuning			tuning;
extern t_mutex			mutex;
extern t_term_color		cl;
extern t_benchmark		bench;
extern t_fifo_pkt		fifo;///!<packets fifo
extern t_hash 				*sessions;
extern t_hash				*hosts;
extern t_hash				*softwares;
extern t_hash				*macprefix;
extern t_hash				*errors;
extern t_hash				*users;
extern t_hash				*users2users;
extern t_tab_services			services;

//rule engine
extern t_traffic_rules_nb	rules_nb;
extern	struct	pcap_stat*	ps;

void benchmark_hash();
void benchmark_rule();
void benchmark_throughput(_s32 t);

//traf units
static char *traf_unit[] = {
	"b",
	"Kb",
	"Mb",
	"Gb",
};

void benchmark(_s32 t)
{
	_s32 d = 0;
	d = time(NULL) - t;
	d = d ? d : 1;
	out("\nBenchmark\n-----------\n");
	out("Time for Analysis:\t\t%d sec\n",d);
	
	if(option.fname != NULL)
		out("Num of packets processed:\t%lld\nPackets by sec:\t\t\t%lld/s\n", bench.nbpkt, bench.nbpkt/d);
	else
		out("Num of packets processed : %d\nNum of packet loose %d\n", ps->ps_recv, ps->ps_drop);
	

	benchmark_throughput(d);
	benchmark_hash();
	benchmark_rule();

	//speclial hidden functionnality for sanity automated test.
	if(option.fancy == 2)
		printf("p:%lld f:%lld\n", bench.nbpkt, bench.freepkt);
}

void benchmark_throughput(_s32 t)
{
	_s64	value = 0;
	_u8	type = 0;
	value = (bench.len * 8);
	if((value - 1073741824) > 1) {
		type = 3;
		value /= 1073741824;;
	} else if (value - 1048576 > 1) {
		type = 2;
		value /= 1048576;
	} else  if (value - 1024 > 1) {
		type = 1;
		value /= 1024;
	}
	
	out("Num of Bytes processed:\t\t%lld %s\n", value, traf_unit[type]);
		
	value = (bench.len * 8)/ t;
	if(value - 1073741824 > 1) {
		type = 3;
		value /= 1073741824;
	} else if (value - 1048576 > 1) {
		type = 2;
		value /= 1048576;
	} else  if (value - 1024 > 1) {
		type = 1;
		value /= 1024;
	}
	
	out("Throughput:\t\t\t%lld %s/s\n", value, traf_unit[type]);
}
void benchmark_hash()
{
	out("\nHash Stats\n-----------\n");
	out("Flow\t\t nb:%10d\tcollisions:%10d\tratio:%d \%\n",sessions->entrycount, sessions->collision, sessions->entrycount ? ((sessions->collision * 100)/sessions->entrycount) : 0);
	out("Hosts\t\t nb:%10d\tcollisions:%10d\tratio:%d \%\n",hosts->entrycount, hosts->collision, hosts->entrycount ? ((hosts->collision * 100)/hosts->entrycount) : 0);
	out("Softs\t\t nb:%10d\tcollisions:%10d\tratio:%d \%\n",softwares->entrycount, softwares->collision, softwares->entrycount ? ((softwares->collision  * 100)/softwares->entrycount) : 0);
	out("Errors/Events\t nb:%10d\tcollisions:%10d\tratio:%d \%\n",errors->entrycount, errors->collision, errors->entrycount ?  ((errors->collision * 100)/errors->entrycount) : 0);
	out("Users\t\t nb:%10d\tcollisions:%10d\tratio:%d \%\n",users->entrycount, users->collision, users->entrycount ? ((users->collision * 100)/users->entrycount) : 0);
}
void benchmark_rule()
{	out("\nRules Stats\n-----------\n");
	out("Protocol:\t%d\nClient:\t\t%d\nServer:\t\t%d\nFile:\t\t%d\nUser:\t\t%d\nUserrelation:\t%d\nEvent:\t\t%d\n", rules_nb.pcount, rules_nb.ccount, rules_nb.scount, rules_nb.fcount, rules_nb.ucount, rules_nb.rcount, rules_nb.ecount);
}
