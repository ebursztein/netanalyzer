/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/**!
* This file is used to define all the constants
* need by the programm
*/
#ifndef _CONSTANT_H
#define _CONSTANT_H 1

///\!\todo add it in tweak option in configuration file
//Session Timeout Constant
#define SESS_REGULAR_TIMEOUT	62 //a la netflow
#define SESS_BROADCAST_TIMEOUT 7200

//pcap timeout value ms
#define PCAPTIMEOUT 		10

///\!\todo add it in tweak option in configuration file

//default max number in fifo 
#define FIFO_SIZE	500
//default max size beforre releasing the fifo
#define FIFO_TIME	5

//default confidence percentage in port heuristic
#define PORT_HEURISTIC_DEFAULT 70

// intervall for calculating the stats
#define   DEFAULT_TIME 		30

///\!\todo be sur we handle the number of capture

// number of time the stats is displayed before exit, -1 for infinite. 
#define   DEFAULT_CAPTURE 	1
// default snaplen
#define DEFAULT_SNAPLEN 	1500

// pcap interface type ethernet
#define 	PI_ETHER	1

// sum traf IN
#define TRAF_IN 	1
	
// sum traf out
#define TRAF_OUT	2

//SESSION STATUS
#define NEWCONN 	0
#define	CONTINUE	1

//Service 
#define SERVICEMATCH_REGEX 1

//socket max message
#define MAXMSG 1024
//socket protocol op code
#define QUIT 		42
#define MAX_PROTO	65536 	/* size of the hach table */
#define	MAX_PROTO_LEN	25 	/* size of proto field in t_func_proto */

//structure block size

#define 	BUFF_S 		64
#define		BUFF_M		128
#define		BUFF_L		256
#define 	BUFF_XL		512
#define 	BUFF_XXL	1024
#define 	BUFF_XXXL	2048

///\!\todo add it in tweak option in configuration file
//hash table stuff
#define HASH_LOAD 	0.65

//Sanity info
#define SANITY_OK	1


//soft constants
#define SOFT_STANDALONE 1
#define SOFT_SESSION	2


//fancy color definition
#define RED	"\033[31m"
#define BRED	"\033[1;31m"
#define GRE	"\033[32m"
#define BGRE	"\033[1;32m"
#define YEL	"\033[33m"
#define BYEL	"\033[1;33m"
#define BLU	"\033[34m"
#define BBLU	"\033[1;34m"
#define PUR	"\033[35m"
#define BPUR	"\033[1;35m"
#define CYA	"\033[36m"
#define BCYA	"\033[1;36m"
//fancy special
#define CLR	"\033[0m"
#define ALRT	"\033[1;41m"

//Tcpdump output like color structure
typedef struct	s_term_color
{
	char	*red;
	char	*bred;
	char	*gre;
	char	*bgre;
	char	*yel;
	char	*byel;
	char	*blu;
	char	*bblu;
	char	*pur;
	char	*bpur;
	char	*cya;
	char	*bcya;
	char	*clr;
	char	*alrt;
}t_term_color;


#endif

//PARSSING const
#ifndef EXIT_FAILURE
#define EXIT_FAILURE    -1
#endif


#ifdef HAVE_PCRE_PCRE_H
# include <pcre/pcre.h>
#else
# include <pcre.h>
#endif
