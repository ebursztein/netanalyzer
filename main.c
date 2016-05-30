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
 *	\file main.c
 *	\brief Entry point of the programm (main.c).
 *
 *	This file is used for, main() function, parsing argv thread handeling and init functions.
 *	\author  Elie
 *	\version 3.0
 *	\date    2007
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


t_option			option;
t_analyze			analyze;
t_tuning			tuning;
t_mutex				mutex;
t_term_color			cl;
t_benchmark			bench;
t_fifo_pkt			fifo;///!<packets fifo
	
extern	struct	pcap_stat*	ps;

t_hash 				*sessions;
t_hash				*hosts;
t_hash				*softwares;
t_hash				*macprefix;
t_hash				*errors;
t_hash				*users;
t_hash				*users2users;
t_tab_services			services;

//rule engine
extern t_traffic_rules_nb	rules_nb;
//control packets rules
t_traffic_protocol	*protocol_patterns;
t_traffic_software	*client_patterns;
t_traffic_software	*server_patterns;
t_traffic_file		*file_patterns;
t_traffic_user		*user_patterns; 
t_traffic_user_to_user	*user_to_user_patterns;

//data packets rules
t_traffic_protocol	*dprotocol_patterns;
t_traffic_software	*dclient_patterns;
t_traffic_software	*dserver_patterns;
t_traffic_file		*dfile_patterns;
t_traffic_user		*duser_patterns; 
t_traffic_user_to_user	*duser_to_user_patterns;

 extern	_u32		parser_recurse;

/*!
 * The main function
 * @param argc arg count.
 * @param argv arg value.
 * @see usage()
 * @return the status of exit
 * \version 2
 * \date   July 2006
 * \author Elie
 */

int	main(int argc, char **argv)
{
  _s8  c;

  //thread used by the collector
  pthread_t collector, decoder, stateful, traffic, application, output;

  // Initializes the different variables and structures
  setup_default();
  ///!\todo FIXME:HANDLE output type : ALL NETWORK HOST PROTOCOL SESSIONS
  // Reads the options from argv
  while ((c = getopt(argc, argv, "a:bcd:i:l:p:qr:s:t:u:w:xof:d:e:h:m:ADEFHLMNUSI")) != -1)
    switch (c)
    {
//analyze option
	case 'A':
		analyze.advanced = -1;
		break;
	case 'D':
		    tuning.dump_profile = 1;
		    break;
	case 'L':
		if(!analyze.tcpdump)
			analyze.tcpdump = -1;
		break;
	case 'E':
		if(!analyze.sanity)
		{
			analyze.sanity 	= -1;
			analyze.error	= -1;
		}
		break;
	case 'I':
	    	if(!analyze.sanity)
			    analyze.event 	= -1;
		break;
	case 'H':
		if(!analyze.host)
			analyze.host = -1;
		break;
	case 'S':
		if(!analyze.software)
			analyze.software = -1;
		break;
	case 'N':
		if(!analyze.network)
			analyze.network = -1;
		break;
	case 'P':
		if(!analyze.protocol)
			analyze.protocol = -1;
		break;
	case 'U':
		if(!analyze.user)
			analyze.user = -1;
			break;
	case 'F':
		if(!analyze.session)
			analyze.session = -1;
			break;
	case 'a':
		option.configuration = (char *)my_strndup(optarg, strlen(optarg));
		break;;
	case 'e':
		analyze.sanity = atoi(optarg);
		analyze.error = atoi(optarg);
		break;
	case 'h':
		analyze.host = atoi(optarg);
		break;
	case 'p':
		analyze.protocol = atoi(optarg);
		break;
	case 'q':
		option.quiet = 1;
		break;
	case 's':
		analyze.software = atoi(optarg);
		break;
	case 'u':
		analyze.user = atoi(optarg);
		break;
	case 'f':
		analyze.session = atoi(optarg);
		break;
	case 'x':
		option.xml = 1;
		break;
	
	case 'c':
		option.fancy++;
		break;
	case 'd':
		option.debug = atoi(optarg);
		break;
	case 'b':
		option.benchmark++;
		break ;
	case 'i':
		option.interface = (char *)my_strndup(optarg, strlen(optarg));
		break ;
	case 't':
		option.intervall = atoi(optarg);
		break ;
	case 'n':
		option.number = atoi(optarg);
		break ;
	case 'r':
		option.fname = (char *)my_strndup(optarg, strlen(optarg));
		option.intervall = 0;
		break;
	case 'l':
		option.snaplen = atoi(optarg);
		break ;
	case 'k':
		option.setuid = atoi(optarg);
		break;
	case 'w':
		option.fileout = fopen(optarg, "w+");
		break;
	case 'o':
	 	option.errout = fopen(optarg, "w+");
		break;
	case '?':
	default:
	usage(argv[0]);
    }

      argc -= optind;
  argv += optind;

  // Uses the rest of the args for the pcap_filter
  make_filter_from_trailing_args(argc, argv);
  //do we need the advanced analyzer ?
  ///!\todo break adavance analyze to be more modulars
  if (analyze.software || analyze.user)
	  analyze.advanced = -1;
  
	//post parsing init
	post_parsing_init();
  if(option.debug == 1)
    printf("Extended filter is %s\n", option.extfilter);
  
  if(option.fileout == NULL)
    	option.fileout = stdout;
  
  if(option.errout == NULL)
	option.errout = stderr;

  ///!\todo FIXME:can we read file in deamon mode ? in a clean way ? with no hack ? not sure...    ?
  if (option.fname != NULL && option.deamon > 0)
    die("OUPS : can't read a file and be in deamon mode...");

  ///!\todo FIXME:we write in a socket or in a file not both (any interessed to do both ?
  if (option.fileout != stdout && option.deamon > 0)
    die("OUPS : can't write a file and be in deamon mode...");

  //setting up default output to all if no output specic
    if(!analyze.tcpdump && !analyze.all && !analyze.network && !analyze.host && !analyze.protocol && !analyze.session && !analyze.software&& !analyze.sanity && !analyze.user)
      usage(argv[0]);
    
    if(analyze.tcpdump && (analyze.all || analyze.network || analyze.host || analyze.protocol || analyze.session || analyze.software))
      printf("%sWarning output can be unreadable\n", cl.red);

  if (option.fname != NULL)
	 //locking the output until we finish reading file
	 pthread_mutex_lock(&mutex.readover);
  
  	// Lauches the collector thread
	pthread_create(&collector, NULL, (void*)&collector_function, NULL);
	mutex.thread_sync = THREAD_START_COL;
	//usleep(ms_to_sleep); //be sure network file system are ready and every thread start correctly
  	
	// Lauches the decoder thread
  	pthread_create(&decoder, NULL, (void*)&decoder_function, NULL);
  	mutex.thread_sync = THREAD_START_DEC; 
	//usleep(ms_to_sleep);
  	
	//Lauches the stateful thread
  	pthread_create(&stateful , NULL,(void*)&stateful_function, NULL);
	mutex.thread_sync = THREAD_START_STA;
	//usleep(ms_to_sleep);
    	
	//Lauches the traffic thread
    	pthread_create(&traffic , NULL,(void*)&traffic_function, NULL);
	mutex.thread_sync = THREAD_START_TRA;
	//usleep(ms_to_sleep);
	
	//application layer
	pthread_create(&application , NULL,(void*)&application_function, NULL);
	mutex.thread_sync = THREAD_START_AP;
	
	//Lauches the output thread
    	pthread_create(&output , NULL, (void*)&output_function, NULL);
	mutex.thread_sync = THREAD_START_OUT;
	//usleep(ms_to_sleep);
	
	// Waiting for thread to exit

  	//COLLECTOR
 	 pthread_join(collector, NULL);
  	if(option.debug == 2)
    		printf("collector has return\n");

  	//decoder
	mutex.thread_sync_stop = THREAD_STOP_DEC;
	pthread_join(decoder, NULL);
	if(option.debug == 2)
    		printf("decoder has return\n");

  	//stateful
	mutex.thread_sync_stop = THREAD_STOP_STA;	
  	pthread_join(stateful, NULL);
	if(option.debug == 2)
    		printf("stateful has return\n");

  	//traffic
	mutex.thread_sync_stop = THREAD_STOP_TRA;	
    	pthread_join(traffic, NULL);
	if(option.debug == 2)
    		printf("traffic has return\n");

	 //STATS
	mutex.thread_sync_stop = THREAD_STOP_AP;	
    	pthread_join(application, NULL);
	if(option.debug == 2)
    		printf("application has return\n");
	
	if (option.fname != NULL)
	{
		if(option.debug == 2)
			printf("unlock readover\n");
	  //locking the output until we finish reading file
		pthread_mutex_unlock(&mutex.readover);
	}
  	//OUTPUT
	mutex.thread_sync_stop = THREAD_STOP_OUT;	
    	pthread_join(output, NULL);
	if(option.debug == 2)
    		printf("output has return\n");


  if(option.debug == 2)
    printf("Analyze finish\n");

  return 42;
}

/*!
 * Initializes the different variables and struct
 * \version 1
 * \date   July 2006
 * \author Elie
 */
void	setup_default()
{
  
///!\todo finish to port default option to configuration
  option.benchmark		= 0;
  option.fancy			= 0;
  option.number			= 0;
  option.interface		= NULL;
  option.pcaptimeout		= PCAPTIMEOUT;
  option.filter			= NULL;
  option.extfilter		= NULL;
  option.debug			= 0;
  option.interface_type 	= -1;
  option.fname			= NULL;
  option.fileout		= NULL;
  option.netp			= 0;
  option.maskp			= 0;
  option.pkt_num		= 0;
  option.host_num		= 0;
  option.session_timeout	= SESS_REGULAR_TIMEOUT;
  option.broadcast_timeout	= SESS_BROADCAST_TIMEOUT;

  //initilizing tuning option
  bzero(&tuning, sizeof(t_tuning));
  
  tuning.fifo_size = FIFO_SIZE;
  tuning.fifo_max_time = FIFO_TIME;
  
  //be sur that queue are at least processed one time between display intervall
  if(tuning.fifo_max_time > option.intervall)
	  tuning.fifo_max_time = option.intervall / 2;
  tuning.port_heuristic_confidence = PORT_HEURISTIC_DEFAULT;
  
		  
  //intilizing output
  bzero(&analyze, sizeof(t_analyze));
  //init bench
  bzero(&bench, sizeof(t_benchmark));
  //inti packet fifo
  bzero(&fifo, sizeof(t_fifo_pkt));
  //hash structure init
  sessions	= session_init();
  hosts 	= host_init();
  macprefix 	= macprefix_init();
  softwares 	= software_init();
  errors 	= error_init();
  users		= user_init();
  users2users	= user2user_init();
  	//protocols structures
	protocol_init();

	//rule engine structures
	protocol_patterns 	= NULL;
	client_patterns	 	= NULL;
	server_patterns 	= NULL;
	file_patterns 		= NULL;
	user_patterns		= NULL; 
	user_to_user_patterns	= NULL;
	dprotocol_patterns	= NULL;
	dclient_patterns	= NULL;
	dserver_patterns	= NULL;
	dfile_patterns		= NULL;
	duser_patterns		= NULL; 
	duser_to_user_patterns	= NULL;

  bzero(&rules_nb, sizeof(t_traffic_rules_nb));
  services_init();
  //initilizing mutex
  pthread_mutex_init(&mutex.col2dec, NULL);		
  pthread_mutex_init(&mutex.dec2sta, NULL);		
  pthread_mutex_init(&mutex.sta2tra, NULL);		
  pthread_mutex_init(&mutex.tra2app, NULL);		
  pthread_mutex_init(&mutex.app2out, NULL);		
  
  pthread_mutex_init(&mutex.readover, NULL);
  pthread_mutex_init(&mutex.processover, NULL);

  pthread_mutex_init(&mutex.hashsession, NULL);
  pthread_mutex_init(&mutex.hasherror, NULL);
  pthread_mutex_init(&mutex.hashsoftware, NULL);
  pthread_mutex_init(&mutex.hashhost, NULL);
  pthread_mutex_init(&mutex.hashuser, NULL);
  pthread_mutex_init(&mutex.hashuser2user, NULL);
  
  
  mutex.thread_sync		= 0;
  mutex.thread_sync_stop	= 0;

  //parser global
  parser_recurse = 0;
}

/*!
 * Post argument parsing initinialization function
 * Ensuring that everything is ok. Dont trust user
 * \version 1
 * \date   July 2006
 * \author Elie
 */
void post_parsing_init()
{
	FILE	*fp;
  	//parsing config file
  	if(option.configuration)
		parse_conf(option.configuration);
	else if ((fp = fopen("conf/netanalyzer.cfg", "r")) != NULL)
	{
		option.conf_path = (char *)my_strndup("conf/", strlen("conf/"));
		parse_conf("netanalyzer.cfg");
	}
	else if ((fp = fopen("/etc/netAnalyzer/netanalyzer.cfg", "r")) != NULL) {
		option.conf_path = (char *)my_strndup("/etc/netAnalyzer/", strlen("/etc/netAnalyzer/"));
		parse_conf("netanalyzer.cfg");
	} else {
		die("Configuration file is missing: can't parse conf/netanalyzer.cfg or /etc/netAnalyzer/netanalyzer.cfg\n");
	}
	//make fancy
	init_fancy();
	if (tuning.weight_port == 0)
		die("Tuning option weight_port need to be specified\n");
	if (tuning.weight_pattern == 0)
		die("Tuning option weight_pattern need to be specified\n");
	if (tuning.weight_profile == 0)
		die("Tuning option weight_profile need to be specified\n");	
}

/*!
 * Used argument left to create the filter both pcap and lvl 7 regexp one.
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param argc arg count.
 * @param argv arg value.
 * @see usage()
 * @return nothing usefull
 */
char	*make_filter_from_trailing_args(int argc, char **argv)
{
  char  *filter = NULL;
  char  *tmp = NULL;
  char 	*extfilter = NULL;
  _u32   len;
  _u16   i;

	if (!argc)
		return NULL;
	len = strlen(argv[0]);
  	filter = (char *)malloc(len + 1);
	strcpy(filter, argv[0]);
   for (i = 1; i < argc && argv[i][0] != ':' ; i++)
   {
	   tmp = filter;
	   len += strlen(argv[i]) + 2; //\0 + " "
	   filter  = malloc(len);
	   strcpy(filter, tmp);
	   strcat(filter, " ");
	   strcat(filter, argv[i]);
	   free(tmp);
   }
   option.filter = filter;
   if (i == argc || (i + 1 ) == argc)
	   return NULL;
   	i++;
	len = strlen(argv[i]);
	extfilter = malloc(len + 1);
	strcpy(extfilter, argv[i]);
	for (i++; i < argc; i++)
   	{
	   tmp = extfilter;
	   len += strlen(argv[i]) + 2; //\0 + " "
	   extfilter  = malloc(len);
	   strcpy(extfilter, tmp);
	   strcat(extfilter, " ");
	   strcat(extfilter, argv[i]);
	   free(tmp);
	 }
	
	
	die("%s\n",extfilter);
  /*
  for (i = 0, len = 0; i < argc && argv[i][0] != ':' ; i++)
  {
    len += strlen(argv[i]);
    //Args left ?
    len += (i < (argc - 1)) ? 1: 0;
    tmp = str;
    str = malloc(len);
    printf("tmp:%s str:%s len:%d",tmp, str, len);
    if (tmp != NULL)
   	 ;
	    //  strcat(str, tmp);
    free(tmp);
    //str = strcat(str, argv[i]);
    if (i < (argc - 1))
	    
     // str = strcat(str, " ");
  }
  option.filter = str;

  for (i += 1, len = 0, str = tmp = NULL; i < argc; i++)
  {
    len += strlen(argv[i]);
    //Args left ?
    len += (i < (argc - 1)) ? 1: 0;
    tmp = str;
    str = malloc(len);
    if (tmp)
    {
      strcat(str, tmp);
    }
    strcat(str, argv[i]);
    if (i < (argc - 1))
      strcat(str, " ");
  }
  option.extfilter = str;
  */
  return NULL;
}

/*!
 * Used to instentiate termcaps if requested by the user.
 * \version 1
 * \date   July 2006
 * \author Elie
 */
void	init_fancy()
{
  if (option.fancy)
  {
    cl.red = 	RED;
    cl.bred =	BRED;
    cl.gre =	GRE;
    cl.bgre =	BGRE;
    cl.yel =	YEL;
    cl.byel =	BYEL;
    cl.blu =	BLU;
    cl.bblu =	BBLU;
    cl.pur =	PUR;
    cl.bpur =	BPUR;
    cl.cya =	CYA;
    cl.bcya =	BCYA;
    cl.clr =	CLR;
    cl.alrt =	ALRT;

  } else {

    cl.red =	"";
    cl.bred =	"";
    cl.gre =	"";
    cl.bgre =	"";
    cl.yel =	"";
    cl.byel =	"";
    cl.blu =	"";
    cl.bblu =	"";
    cl.pur =	"";
    cl.bpur =	"";
    cl.cya =	"";
    cl.bcya =	"";
    cl.clr =	"";
    cl.alrt =	"";
  }
}
/*!
 * if arguments are invalid or if help request : display usage information and exit
 * \version 1
 * \date   July 2006
 * \author Elie
 * @param name name of the programm
 */
void	usage(char *name)
{
  if (name)
	  die("usage: %s [options] [filter expression (pcap filter:regexp filter)]\nAnalysis selection:\n[-F flows][-H hosts] [-P protocol] [-L LiveDump (error and event)] [-E errors] [-I info/event] [-S map softwares] [-U users][-A advanced traffic inspection][-D dump packet profile]\nAnalysis display limit\n[-f number of flows] [-h number of hosts] [-s number of software] [-p number of protocol][-u limite users][-e limit errors]\nOuput options\n[-c colorize output] [-x xml output] [-q quiet (reduced size)] [-w filename for the output] [-o filename for error log]\nOther options\n [-a alternate configuration file] [-i interface] [-l snaplen] [-b benchmark] [-k run as given uid (online mode)] [-t time between display (sec) online mode] [-r pcap filename to read (offline mode)] \n", name);
  else
	  die("usage: %s [options] [filter expression (pcap filter:regexp filter)]\nAnalysis selection:\n[-F flows][-H hosts] [-P protocol] [-L LiveDump (error and event)] [-E errors] [-I info/event] [-S map softwares] [-U users][-A advanced traffic inspection][-D dump packet profile]\nAnalysis display limit\n[-f number of flows] [-h number of hosts] [-s number of software] [-p number of protocol][-u limite users][-e limit errors]\nOuput options\n[-c colorize output] [-x xml output] [-q quiet (reduced size)] [-w filename for the output] [-o filename for error log]\nOther options\n [-a alternate configuration file] [-i interface] [-l snaplen] [-b benchmark] [-k run as given uid (online mode)] [-t time between display (sec) online mode] [-r pcap filename to read (offline mode)] \n", "NetAnalyzer");
}
