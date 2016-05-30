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
 *	\file structure.h
 *	\brief Netanalyzer main structures and their constants.
 *
 *	This file is used to regroup all the main structure used for netanalyzer.
 *	Structure use as base for every perpsective are regrouped here, plus core structure
 * 	such as the packet structure.
 *	\author  Elie
 *	\version 1.1
 *	\date    Dec 2006
 */
 
#ifndef _STRUCTURE_H
#define _STRUCTURE_H

#if defined(__NetBSD__) ||  defined(__OpenBSD__) 
#include <pthreads.h>
#endif
#if defined(__FreeBSD__)
#include <pthread.h>
#endif
#include <stdio.h>
#include "types.h"
#include "protcols_structure.h"
#include "constant.h"
#include "sanity.h"
//#include "traffic_inspection.h"


/*!
\struct t_service
\brief service informations
hold informations about a service such as name defaultport etc
 */
typedef struct s_service
{
	char 	*name;		///!<protocol name
	char	*info;		///!<protocol detailled information
	///protocol profile stored here maybe
} t_service;


/*!
\struct t_tab_service
\brief services array
Array of t_service structures used to acces them quickly
 */
typedef	struct	s_tab_services
{
	t_service	udp[65536];
	t_service	tcp[65536];
	t_service	icmp;
	t_service	arp;
	t_service	ip;
	t_service	ethernet;
	t_service	unknown;
} t_tab_services;


/*!
\stuct t_benchmark
\brief used to store various counter used in intern and for benchmarking
*/
typedef struct s_benchmark
{
	_s64	startime;
	_s64	stoptime;
	_u64	nbpkt;		///!< number of packets so far
	_u64	freepkt;	///!< number of packets freeded
	_s64	len;		///!<total in octect
	// unique identifier for all type
	_u64	session_id; 	///!< session unique id
	_u64	host_id;	///!< number of host unique id
	_u64	software_id;	///!< number of soft unique id
	_u64	file_id;	///!< number of file unique id
	_u64	user_id;	///!< number of user unique id
	_u64	u2u_id;		///!< number of user to user unique id
	_u64	error_id;	///!< number of error unique id
	_u64	event_id;	///!< number of event unique id
	//signatures
	_u64	sigproto; 	///!< number of control protocol signature
	_u64	sigserver; 	///!< number of control server signature
	_u64	sigclient; 	///!< number of control client signature
	_u64	sigfile; 	///!< number of control file signature
	_u64	siguser; 	///!< number of control user signature
	_u64	sigdproto; 	///!< number of control protocol signature
	_u64	sigdserver; 	///!< number of data server signature
	_u64	sigdclient; 	///!< number of data client signature
	_u64	sigdfile; 	///!< number of data file signature
	_u64	sigduser; 	///!< number of data user signature
		
} t_benchmark;


/*!
\struct t_option
\brief for programm options

hold all the options specified by the user except for the choice of the analysis to run
 */
typedef struct s_option
{
  _u8			benchmark; 		///!<benchmarking 
  _u8			fancy;			///!< use termcap
  _u8			xml;			///!<output in xml
  _u8			quiet;			///!<quiet output used to reduce verbosity 
  _u8			number;			///!< number of packet before exit
  _s32			intervall;		///!<Time intervall between making stats 
  _s64			startime; 		///!<using _s64 to calculate the duration of capture from offline capture
  char			*interface; 		///!< interface name
  _s32			snaplen;		///!< snaplen of the packet
  _s32			pcaptimeout;		///!< pcap timeout (macosX handle it... who believe that ?)
  char			*filter;		///!< the pcap filter
  char			*extfilter;		///!< extended filter : extend pcap
  _s32			debug;			///!< for debug
  _s32			interface_type; 	///!< interface type
  char			*fname;			///!< file name for offline sniff
  FILE			*fileout;		///!< output file
  FILE			*errout;		///!< error log fil
  char			*configuration;		///!< alternate configuration file 
char			*conf_path;		///!< path where the configuration file are stored. used to parse include
  _u32			maskp;			///!< Subnet mask
  _u32			netp;			///!<broadcast address
  _u32			pkt_num;		///!<last pkt captured (for tracing)
  _u32			host_num;		///!<last host (for tracing)
  _u32			deamon;			///!<binding a socket ?
  _u32			setuid;			///!<run as specified user
  _u32			session_timeout;	///!<Session time out
  _u32			broadcast_timeout; 
} t_option;

/*!
\struct t_output
\brief for programm output

hold all the informations regarding the output : what and how much to output
 */
typedef struct s_analyze
{
	_s32					all;			///!<output everything
	_s32					network;		///!<output network information
	_s32					host;			///!<output host information (nb if specified or -1 for all)
	_s32					host_stated; 		///!<nb of hosts in the hosts_list
	_s32					protocol;		///!<output protocol info
	_s32					session;		///!<output session information
	_s32					session_stated; 	///!<nb of sessiosn  in the sessions_list
	_s32					user;			///!<output user analyze
	_s32					user_stated;
	_s32					user2user_stated;	///!<user to user
	_s32					software;		///!<output software maping information
	_s32					software_stated;	///!<nb of softwares in the softwares_list
	_s32					tcpdump;		///!<output live 
	_s32					error_stated;		///!<nb of errors in the errors_list
	_s32					sanity;			///!<output sanity analysis results !!! deprecated
	_s32					error;			///!<output error equivalent to sanity
	_s32					event;			///!<output event
	_s32					advanced;		///!<activate advanced inspection
} t_analyze;


#define 	ANALYZE_ISRDY			1
#define 	ANALYZE_TOCLEAN			2
#define   	ANALYZE_TOFLUSH			3



/*!
\struct t_tuning
\brief analyze performance tunning
*
* Used to store tuning information on the analyze
*/
 
typedef struct s_tuning {

	_u8	port_heuristic_confidence;	///!<default percentage confidence in port heuristic
	_u32	weight_port;			///!<how much port weight in protocol identification
	_u32	weight_pattern;			///!<how much pattern weight in protocol identification
	_u32	weight_profile;			///!<how much profile weight in protocol identification
	_u8	proba_display;			///!<under which proba do we need to display ?
	_u8	usedirectionnal;		///!<do we split the advanced analysis to follow direction ?
	_u8	useprofile;			///!<use profile analysis
	_u8	profile_restrict_len; 		///!<restrict the profile inspection to the first n bytes of payload 
	_u32	usepattern;			///!<use pattern analysis
	_u8	usetrafficpattern;
	_u8	useserverpattern;
	_u8	useclientpattern;
	_u8	usefilepattern;
	_u8	useuserpattern;
	_u8	useu2upattern;
	_u8	useerrorpattern;
	_u8	patternsignaturemultimatch;	///!<force the analyzer to keep matching even if a signature is found in stream
	_u8	useadvancedtracking;		///!<advanced tracking to avoid injection/evasion
	_u8	patternrestrictlen;		///!<used to restrict the patern match to the n first bytes of payload to speedup the analysis
	_u8	usechkcover;			///!<use protocol chksum to discover cover channel
	_u16	nbpktinit;			///!<number of packet of init phase where we look to signature
	_u16	dump_profile; 			///!<use the analyzer to dump the profile of each packet in stdin
	_u16	contentpktnum;			///!<used to restict the pattren match to the n first packet of each object
	_s64	fifo_size;			///!<max packet in fifo  between swap (can be a little more at the time of the test)
	_u64	fifo_max_time;			///!<max time between swap in sec (can be a little more)
} t_tuning;

/*!
\struct t_mutex
\brief for program mutex used in thread scheduling

\attention do not ever mix sync notifier with stop modifier it will create deadlock
*/

typedef struct		s_mutex
{
	pthread_mutex_t	col2dec;		///!<passing from collector to decoder
	pthread_mutex_t	dec2sta;		///!<decoder to stateful
	pthread_mutex_t	sta2tra;		///!<stateful to traff
	pthread_mutex_t	tra2app;		///!<traff to ap
	pthread_mutex_t	app2out;		///!<ap to out
	pthread_mutex_t	readover;		///!<in case of reading a file lock the output until it's over
	pthread_mutex_t processover;		///!<ensure that queue processing is over there is a delay between the last packet is read and is processed
	
	pthread_mutex_t hashsession;		///!<ensure that the hash host is not done at the same time by decoder thread ans analyzer  
	pthread_mutex_t hasherror;		 
	pthread_mutex_t hashsoftware;	
	pthread_mutex_t hashhost;		
	pthread_mutex_t hashuser;		
	pthread_mutex_t hashuser2user;		
	


	_s8		thread_sync;		///!<thread sync notifier
	_s8		thread_sync_stop;	///!<thread sync stop notifier
} t_mutex;

#define 	THREAD_START_COL	1
#define 	THREAD_START_DEC	2
#define 	THREAD_START_STA	3
#define 	THREAD_START_TRA	4
#define 	THREAD_START_AP		5
#define 	THREAD_START_OUT	6
#define 	THREAD_STOP_COL		7
#define 	THREAD_STOP_DEC		8
#define 	THREAD_STOP_STA		9
#define 	THREAD_STOP_TRA		10
#define 	THREAD_STOP_AP		11
#define 	THREAD_STOP_OUT		12



typedef struct s_host
{
	//layer 3
	_u32		ip;			/* IP address */
	_u64		id;			//uniq id
	_u64		crc;	
	_u8		arp[ETHER_ALEN]; 	//current arp
	char		*ethervendor;		///!<store the vendor name of the ethernet card
	_u8		arp_flip;		//arp flipping ?
	_u32		sanity;			/* this host is on local network  is it a gate (stats), nat (stats) */
	_s64		last_time;		//*when
	_u16		ttl[BUFF_L];		/* ip ttl */
	_u32		infos; 			//use dhcp, is a gate
	_u8		distance;		//hop distance
	//layer 7
	char		hostname[BUFF_M];
	char		netbios_hostname[BUFF_M];
	char		passive_os_type[BUFF_M];
	char		passive_os_version[BUFF_M];
	
	//trafic info
	_u32		conn_in;
	_u32		conn_out;
	_u32		nb_pkt_in;
	_u32		nb_pkt_out;
	_s32		bytes_in;
	_s32		bytes_out;
	_u32		request;
	_u32		reply;
	_u32		error;
} t_host;

#define	HOST_FROM		1
#define	HOST_TO			2
#define HOST_DHCP		0x0001
#define HOST_GW			0x0002
#define HOST_SELFARP		0x0004


//protocol
typedef struct s_protocol
{
  _u16		port;
  _u32		nb_pkt_in;
  _u32		nb_pkt_out;
  _s32		bytes_in;
  _s32		bytes_out;
  _u32		conn;		//num of connec
  _u16		file_client;	 ///!<Detected throught traffic engine
  _u16		file_server;	 ///!<Detected throught traffic engine
  _u16		req_client; 	 ///!<Event analysis		
  _u16		req_server; 	 ///!<Event analysis
  _u16		rep_client; 	///!<Event analysis
  _u16		rep_server; 	///!<Event analysis
  _u16		err_client; 	///!<Event analysis
  _u16		err_server;
} t_protocol;

typedef struct	s_tabproto
{
  t_protocol		tcp[65536];
  t_protocol		udp[65536];
  t_protocol		arp;
  t_protocol		ip;
  t_protocol		icmp;
  t_protocol		tudp;  //total tcp
  t_protocol		ttcp;  //total udp
  t_protocol		other;
} t_tabproto;


 /*!
\struct t_software
 \brief used to store informations about softwares involved in networks exhanges
 used to store various informations such as traffic breakdown and fingerprint of every software involved on
  networks exchange
*/

typedef struct	s_software
{
	_u64			id; 			///!<unique id
	_u64			host_id;		///!<host id
	_s32			proto;			///!<layer 3 protocol
	_u32			ip;			///!<ip where live the software, can't do otherwise
	_u16			port;			///!<port in forserver, out for client (client out "should" be random) and there for is 0
	
	_u64			crc; 		///!<used to compute efficiently already in the hash information
	_u64			crc_version;		///!<used to compute efficiently if the version has change
	
	_u32			sanity;			///!<is there any problem detected during the use of this software ?
	
	//temporal
	_s64			first_seen;		///!<when do we see it last ?
	_s64			first_seen_usec;		///!<when do we see it last  usec?
	_s64			last_seen;		///!<when do we see it last ?
	_s64			last_seen_usec;		///!<when do we see it last  usec?
	
	_u32			conn;			///!<num of connection
	
	//data
	_u8			type; 			///!<used to indicate if it is a server / client or both information
	_u8			nature;			///!<direct: net application or indirect: content producer software such as mailer, text writer etc
	char			product[BUFF_M];	///!<softname name
	char			version[BUFF_M];	///!<version
	char			protocol[BUFF_M];	///!<protocol what protocol trigger this rule?? 
	char			familly[BUFF_M];	///!<familly of the software : browser for instance or http for http server mail for a mailer..
	char			info[BUFF_M];		///!<additionnal information
	char			hostname[BUFF_M];	///!<hostname or ip where the soft live (if void:take information from the stream)
	char			ostype[BUFF_M];		///!<operating system according to the soft
	char			devicetype[BUFF_M];	///!<type of device supposed
  	struct s_software	*next;
} t_software;

#define SOFT_CLIENT 	0
#define SOFT_SERVER 	1
#define SOFT_DIRECT	0
#define SOFT_INDIRECT	1



/*!
 \struct t_file
 \brief used to store informations about files tranfered during the networks exhanges
 This structure allow to store informations of files founded during network sessions.
 In particular their name and their familly
*/

typedef struct s_file
{
	_u64				session_id;
	char				name[BUFF_M];
	char				extension[BUFF_M];
	char				familly[BUFF_M];
	char				headers[BUFF_M];
	char				additionnal[BUFF_M];
	_u8				nature;///!<control or data part of the session
	_s64				size;
	long				entropy;///!<predicted entropy according to rules to  match against profile
	_u32				object_pkt_num;///!<detected by the traffic engine
	_u32				object_len;///!<detected by the traffic engine
	//struct t_traffic_profile	profile;///!<store the profile associated with the file 
	struct s_file			*next;
} t_file;


/*!
 \struct t_protocol_info
 \brief used to store informations about protocol returned by the pattern traffic analysis
 This structure allow to store informations of files founded during network sessions.
 In particular their name and their familly
*/
  
typedef struct s_protocol_info
{
	char			name[BUFF_M];
	char			version[BUFF_M];
	char			familly[BUFF_M];
	char			additionnal[BUFF_M];
	char			encrypted[BUFF_M];
	_u8			nature;///!<control or data part of the session
	struct s_protocol_info	*next;
} t_protocol_info;


/*!
 \struct t_error
 \brief used to store informations about events and errors detected on the netwok
 * 
 * The same structure is used for both errors and event because they are similars.
 * the distiction is made by the help of the variable type.
 * Livedump (aka Tcpdump) display this structure in realtime
 */
typedef struct s_error
{
	//base info
	_u64		id;			///!<unique id
	_u8		layer;			///!<TCP/IP layer involve
	_u8		type;			///!<What it is  ? Request, reply or Error
	_u64		crc;			///!<to improve finding			
	
	//Classification Ala snort style : enter the shortname the configuration will do the rest
	char		class_shortname[BUFF_M];///!<classification shortname
	_u16		severity;		///!<error severity
	char		class_details[BUFF_XXL];///!<classification details

	//details
	char		name[BUFF_M];		///!<even name
	char		group[BUFF_M];		///!<even group : leak ? login ? spoofing, transfert ? 
	char		details[BUFF_XXL];	///!<detailled information about it : consequence ?
	char		target[BUFF_M];		///!<About what ? User, password, file ?
	_u8		nature;			///!<can be : "req, rep, err" used for stat counting 
	
	
	//who
	_u64		session_id;		///!<session incriminated
	_u64		host_id;		///!<host incriminated
	_u32		ip;			///!<no session or host ? then at least ip
	
	//temporal
	_u32		frequency;		///!<number of time the error has been seen
	_s64		first_time;		///!<first time the error as been seen
	_s64		first_time_usec;
	_s64		last_time;
	_s64		last_time_usec;

} t_error;

#define LAYER_PHYSICAL		1
#define LAYER_DATA_LINK 	2
#define	LAYER_NETWORK		3
#define	LAYER_TRANSPORT		4
#define LAYER_APPLICATION 	5


/*!
 \struct t_user
 \brief used to store informations about the users that use the network
 */
typedef struct s_user
{
	_u64		id;///!<unique id
	_u64		crc;///!<to improve finding	
	
	//credital
	char		protocol[BUFF_M];
	char		familly[BUFF_M];
	char		login[BUFF_M];
	char		pass[BUFF_M];
	char		algorithm[BUFF_M];///!<algorithm used to crypt
	char		additionnal[BUFF_XL];
	char		origin[BUFF_M];///!<where the user information as been found
	_u8		nature;///!<nature of relation: direct/indirect : direct  relation such as instant messaging or indirect such as mail 
		
	
//hostname
	char		hostname[BUFF_M];
	_u32		ip;
	_u64		host_id;
	
	//temporal
	_s64		last_time;
	_s64		last_time_usec;
	_s64		start_time;///!<first time the user has been seen
	_s64		start_time_usec;
	_u32		frequency;///!<number of time the user has been seen
	
	//analysis
	_u8		pass_strength;///!<password strength estimation
	struct	s_user	*next;
} t_user;


/*!
 \struct t_user_to_user
 \brief	used to store relation between user
 */
typedef struct s_user_to_user
{
	_u64			host_id_src;
	_u64			host_id_dst;
	_u64			id;
	_u64			crc;
	_u32			ip; ///!<ip source of the packet
	//data
	char			sender[BUFF_M];
	char			receiver[BUFF_M];
	char			protocol[BUFF_M];
	char			familly[BUFF_M];
	char			additionnal[BUFF_XL];
	char			origin[BUFF_M];///!<where the user information as been found
	_u8			nature;///!<nature of relation: direct/indirect : direct  relation such as instant messaging or indirect such as mail 
	
	//temporal
	_s64			first_time;///!<first time the relations as been seen
	_s64			first_time_usec;
	_s64			last_time;
	_s64			last_time_usec;
	_u32			frequency;///!<number of time the relation as been seen
	
	struct s_user_to_user	*next;
} t_user_to_user;

#define RELATION_DIRECT 	1
#define RELATION_INDIRECT  	2

/*!
 \struct t_session_protocol
 \brief	used to store protocol feeback and determine the correct protocol
 */
typedef	struct	s_session_protocol
{
	//protoocl name
	char				name[BUFF_S];
	_u32				proba;///!<overall probability computed dynamically 
	
	//proba by techniaue
	_f32				proba_porthint;
	_f32				proba_profile;
	_f32				proba_pattern;
	
	
	//score by technique
	_u16				score_pattern;
	_u16				score_porthint;
	_u16				score_profile;
	
	//origin
	_u16				num_pattern;
	_u16				num_porthint;
	_u16				num_profile;
	struct	s_session_protocol 	*next;
} t_session_protocol;

typedef struct 	s_session
{
	// out 
	_u32		k;			///!<session indek key
	_u64		id;			///!<session number
	t_host	*src_host_id; 	///!<pointer to the host source structure
	t_host	*dst_host_id; 	///!<pointer to the host destination structur
	_u32		client_id;		///!<id of the host source for db relation
	_u32		server_id;		///!<id of the host destination for db relation
	_u8		state;
	_u8		nature; 		///!(unicast, multicast or broadcast)
	_u32		sanity;
	_u16		proto;
  	_u32		src;
	_u32		dst;
	_u16		sport;
	_u16		dport;
	_s64		start_time;
	_s64		start_time_usec;
	_s64		last_time;
	_s64		last_time_usec;
	_s64		last_time_in;
	_s64		last_time_in_usec;
	_s64		last_time_out;
	_s64		last_time_out_usec;
	
	//layer	3 informations
	_u32		nb_pkt_in; //server
	_u32		nb_pkt_out; //client
	_s32		bytes_in;
	_s32		bytes_out;
	
	//ttl tracking
	_u8		default_ttl_in;		///!<use ^2 heuristic or pof
	_u8		default_ttl_out;
	_u8		ttl_in; 			///!<ttl server
	_u8		ttl_out;			///!<ttl client
	_u8		distance_in;		///!<distance of the server
	_u8		distance_out;		///!<distance of the client
		
	//layer 7 informations
	_u16		file_client;	 		///!<Detected throught traffic engine
	_u16		file_server;		///!<Detected throught traffic engine
	_u32		file_client_len;
	_u32		file_server_len;
	_u32		file_client_pkt_num;
	_u32		file_server_pkt_num;
	_u16		req_client; 	 	///!<Event analysis		
	_u16		req_server; 	 	///!<Event analysis
	_u16		rep_client; 		///!<Event analysis
	_u16		rep_server; 		///!<Event analysis
	_u16		err_client; 			///!<Event analysis
	_u16		err_server;		///!<Event analysis

	//protocol detection

	//char			*guessed_protocol;	///!<the guested protocol
	t_session_protocol 	*guessed_protocol;
	_u32			guess_probability;	///!<protocol probability
	_u32			proto_num_pattern; 	///!<number of pattern matched
	_u8			proto_num_porthint;	///!<do we have a port hint
	_u32			proto_num_profile;	///!<number of profiles matched
	t_service		*service;		///!<port int value
	t_session_protocol 	*proto_candidat;	///!<candidat list
	
	//traffic engine
	

	_u8		phase_client;///!<Session phase state according to the traffic engine
	_u8		phase_server;///!<Session phase state according to the traffic engine
	_u32		last_size_client;///!<Used to detect phase change
	_u32		last_size_server;///!<Used to detect phase change
	_u32		file_client_last_len;///!<information on the current file
	_u32		file_server_last_len;
	_u32		file_client_last_pkt_num;
	_u32		file_server_last_pkt_num;
	
	
	//pattern inspection 
	t_protocol_info	*protocol;
	t_protocol_info	*last_protocol;
	t_software	*client;
	t_software	*last_client;
	t_software	*server;
	t_software	*last_server;
	t_file		*file;
	t_file		*last_file;
	t_user		*user;
	t_user		*last_user;
	t_user_to_user	*user2user;
	t_user_to_user	*last_user2user;
} t_session;


#define	SESS_IS_UNICAST 	0
#define	SESS_IS_MULTICAST	1
#define	SESS_IS_BROADCAST	2

#define CONTROL_PHASE  		1
#define DATA_PHASE		2
#define JAM_PHASE		3 //we dont know what we are
#define	PHASE_MINIMAL_SLOP_CONTROL_TO_DATA 1000 //that's 66% of the capacity
#define	PHASE_MINIMAL_SLOP_DATA_TO_CONTROL 555 //that's 33% of the capacity

#define	SERV_TO_CLIENT 1
#define CLIENT_TO_SERV 2

#define SESS_DISP_ALL		1
#define SESS_DISP_BROKEN	30
#define	SESS_SYN		1
#define	SESS_SYNACK		2
#define	SESS_ACK		3
#define	SESS_FIN		4
#define	SESS_FIN2		5
#define	SESS_RST		6
#define	SESS_UDP_OPEN		7
#define SESS_UDP_ESTA		8
#define	SESS_UDP_TIMED		9
#define SESS_PARTIAL_TCP	15
#define	SESS_HALF_OPEN		25
#define SESS_OVERCLOSE		33	//very bad boy already close
#define SESS_BLINDSPOOF		34	//no ack without synack ... mean spoof
#define SESS_TIMEOUT		666	//session is timeouted
/*!
 \struct t_macaddr
 \brief used to store the mac address vendor information
*/

typedef	struct	s_macaddr {
	int prefix;
	char *vendor;
	///!\todo add device type such cisco = network switch / pocketpc or laptop apple ?
} t_macaddr;






typedef struct s_hash_entry
{
	_u32			k;
	t_session 		*s; ///!<session hash
	t_host			*h; ///!<host hash
	t_macaddr		*m; ///!<mac address hash
	t_software		*o; ///!<software hash
	t_user			*u; ///!<user hash
	t_user_to_user		*r; ///!<user to user hash
	t_error			*e; ///!<error hash
	struct s_hash_entry	*next;
	
} t_hash_entry;

#define HASH_SESSION 		1
#define HASH_HOST		2
#define HASH_MAC		3
#define HASH_SOFTWARE		4
#define	HASH_USER		5
#define	HASH_ERROR		6
#define HASH_USER_TO_USER	7

typedef struct s_hash
{
	_u8		type;
	t_hash_entry 	**table;	///!<table of pointer to hash entry
	_u32 		tablelength; 	///!<size
	_u32 		entrycount;  	///!<used
	_u16		primeindex;  	///!<index in prime table
	_u16		collision;	///!<number of collisions
	
} t_hash;

//pkt structure
typedef struct s_pkt
{
	_u64			id;			///!<pkt num captured
	///\todo remove it pkt_num is deprecated
	char			*buf;			///!<pcap buffer captured
	_s16			len;			///!<len of the buffer
	char			*payload;		///!<pointer to the payload
	_s16			payload_len;		///!<len of the payload
	_s64			time_capture;		///!<pcap time of capture
	_s64			time_capture_usec; 	///!<usec of the time of capture
	_s16 			decoded_len; 		///!<decoded len
	_s32 			pkt_proto;		///!<proto of the packet based on protocol.h (negative mean problem)
	_u32			sanity; 		///!<detect problem at pkt lvl
	_u8			tos;			///!<tos info
	_u8			mtu;			///!<mtu info
	
	//session info
	t_session		*s;					///!<the session where the packet belong
  	_u8			phase_client;			///!<store session state at the time of the packet to avoid race condition
	_u8			phase_server;			///!<store session state at the time of the packet to avoid race condition
	_u32			nb_pkt_in; 				///!<store session state at the time of the packet to avoid race condition
	_u32			nb_pkt_out; 			///!<store session state at the time of the packet to avoid race condition
	_s64			last_time;
	_s64			last_time_usec;
	_s64			last_time_in;
	_s64			last_time_in_usec;
	_s64			last_time_out;
	_s64			last_time_out_usec;
  //protocol specific structure
	t_arp			*arp;
	t_ether_addr		*ether_addr;
	t_ether			*ether;
	t_icmp			*icmp;
	t_ip_addr		*ip_addr;
	t_ip			*ip;
	t_tcp			*tcp;
	t_tcp_opt		*tcp_opt;
	t_udp			*udp;
	
	/*t_http			*http;
	t_bootp 		*dhcp;
	t_dns_header		*dns_header;
	t_ftp	 		*ftp;
	t_pop3			*pop3;
	t_imap			*imap;
	t_ssh 	        	*ssh;
	t_smtp			*smtp;
	t_mysql   		*mysql;
	*/
	struct s_pkt		*next;
}t_pkt;

/*!
\struct t_fifo_pkt
\brief Fifo list used to pass packet between threads in a controlled fashion
 */

typedef	struct	s_fifo_pkt
{
	//sanity
	_u64	dec_last_pkt; 	///!<counter used in assert to ensure that we dont miss packet
	_u64	stat_last_pkt;
	_u64	traf_last_pkt;
	_u64	app_last_pkt;
	
	//collector 
	t_pkt	*col;		///!< pointer to first element
	t_pkt	*col_last;	///!< pointer to last element
	t_pkt	*col_next;	///!< pointer to next element to return
	_s64	col_size;	///!< size of the fifo
	_s64	col_processed;	///!< nb pkt of the queue processed
	_u64	col_last_time;	///!< last time it has been updated
	
	//decoder 
	t_pkt	*dec;
	t_pkt	*dec_last;
	t_pkt	*dec_next;
	_s64	dec_size;
	_s64	dec_processed;	///!< nb pkt of the queue processed
	_u64	dec_last_time;
	
	//statful 
	t_pkt	*stat;
	t_pkt	*stat_last;
	t_pkt	*stat_next;
	_s64	stat_size;
	_s64	stat_processed;	///!< nb pkt of the queue processed
	_u64	stat_last_time;
	
	//traffic analyzer 
	t_pkt	*traf;
	t_pkt	*traf_last;
	t_pkt	*traf_next;
	_s64	traf_size;
	_s64	traf_processed;	///!< nb pkt of the queue processed
	_u64	traf_last_time;
	
	//application analyzer
	t_pkt	*app;
	t_pkt	*app_last;
	t_pkt	*app_next;
	_s64	app_size;
	_s64	app_processed;	///!< nb pkt of the queue processed
	_u64	app_last_time;
	
} t_fifo_pkt;




typedef struct s_gateway {
	_u32		ip;		 ///!<IP address
	_u8		arp[ETHER_ALEN]; ///!<current arp
	_u32		hosts;		///!<number of hosts behind it 
	_u8		firewall;	///!<is there any firewall alteration ?
	_u8		nated;		///!<is this a masqueraded gateway ?
} t_gateway;


typedef struct s_chunk {
	char *start;
	char *end;
} t_chunk;


#include "traffic_inspection.h"

#endif
