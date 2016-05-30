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
 *	\file pattern_inspection.h
 *	\brief pattern engine structures, constants, functions.
 *
 *	This file is used to regroup all the structure used for the pattern  inspection
 *	Except the core structures that live in structure.h
 *	\author  Elie
 *	\version 1.0
 *	\date    Dec 2006
 */
 
#ifndef _PATTERN_INSPECT_H
#define _PATTERN_INSPECT_H
#include <pcap.h>


//polymorphism (sic)
#define PROT(r) ((t_traffic_protocol *)(r))
#define SOFT(r) ((t_traffic_software *)(r))
#define FILE(r) ((t_traffic_file *)(r))
#define USER(r) ((t_traffic_user *)(r))
#define UTOU(r) ((t_traffic_user_to_user *)(r))
#define EVEN(r) ((t_traffic_event *)(r))

//define
//control
#define PROTOCOL_PATTERN	1
#define	FILE_PATTERN		2
#define	CLIENT_PATTERN		3
#define SERVER_PATTERN		4
#define	USER_PATTERN		5
#define	USER_TO_USER_PATTERN	6
#define EVENT_PATTERN		7
//data
#define DPROTOCOL_PATTERN	8
#define	DFILE_PATTERN		9
#define	DCLIENT_PATTERN		10
#define DSERVER_PATTERN		11
#define	DUSER_PATTERN		12
#define	DUSER_TO_USER_PATTERN	13
#define DEVENT_PATTERN		14

/*!
\struct t_traffic_rules
 \brief used to count rules loaded
 
 used to for benchmark and debugging
 */

typedef struct s_traffic_rules_nb {
	_u32	pcount; ///!<protocol rules
	_u32	ccount;	///!<client rules
	_u32	scount; ///!<server rules
	_u32	fcount;	///!<file rules
	_u32	ecount; ///!<rules that have a positive 
	_u32	ucount;	///!<user rules
	_u32	rcount; ///!<user to user relation rules
} t_traffic_rules_nb;



/*!
\struct t_traffic_common
\brief used to keep signature common part
 
This structure is used to keep the data common to all the type of signature 
event templates, special keyword, rules priority, the common , its options,  the protocol name and
 */
typedef struct s_traffic_common {
	//protocol
	char				*servicename;
	
	
	//Traffic analyzer feedback
	_u8				next_phase;		///!<used to force to change of the analyzer hint option`
	_u8				type;			///!<can be : "req, rep, err" used for stat counting 
	_u16				confidence;		///!<confidence value
	int 				(*module)();		///!<dynamic module pointer
	_u8				noreport;		///!<dont display rules match
	
	
	//rule policy
	_u8				policy;
	_s32				priority;
	
	
	//classification
	char				*class_shortname;	///!<classification shortname
	
	//event information
	char				*event_name;		///!<even name
	char				*event_nature;		///!<nature of the event: leak ? login ? spoofing, transfert ? 
	char				*event_details;		///!<detailled information about it : consequence ?
	char				*event_target;		///!<About what ? User, password, file ?
	_u8				event_type;		///!<does it need to be report as an error or as  an event ?
	//regex info
	int				offset;			///!<starting offset
	int				depth;			///!<restric to the n byte
	int				matchtype; 		///!< type of match
	char				*matchstr; 		///!<common String to match
	int				matchstrlen; 		///!<len of the common
	char				matchops_ignorecase;	///!< i common option to ignore case
	char				matchops_dotall; 	///!< s common option  PCRE_DOTALL dot matche newlines /s
	char				matchops_multi;		///!< m common option PCRE_MULTILINE  multiple lines match        /m
	pcre 				*regex_compiled; 	///!<the compilated common
	pcre_extra			*regex_extra; 		///!<used for regex study for more speed

} t_traffic_common;	

#define TYPE_ERROR		1
#define	TYPE_EVENT		2

#define	GROUP_REQ		1
#define GROUP_REP		2
#define GROUP_ERR		3

#define RULE_POLICY_STOP 1
#define RULE_POLICY_CONTINUE 2
/*!
\struct t_traffic_protocol
 \brief used to store informations et common used in the protocol pattern inspection 
 
 used to provide level 7 informations about network stream. Two instance exists in the programm
 on for control packets, the other one for data packet.
 */

typedef struct s_traffic_protocol {
	t_traffic_common		*common;		///!<hold common rules information including protocol
	char				*version_template;	///!< version v//
	char				*familly_template;	///!< familly f//
	char				*additionnal_template;	///!< additional i//
	char				*encrypted_template;	///!< crypted c//		
			
	struct s_traffic_protocol	*next;
} t_traffic_protocol;



/*!
\struct t_traffic_software
 \brief used to store informations et common used in the software pattern inspection 
 
 used to provide level 7 informations about network stream. Two instance exists in the programm
 on for control packets, the other one for data packet.
 */
 
typedef struct s_traffic_software {

	t_traffic_common		*common;		///!<hold common rules information including protocol
	//templates
	char 				*product_template; 	///!< product name p// (nmap def)
	char 				*version_template; 	///!< version of the service v// (nmap def)
	char				*familly_template;	///!< familly that the software use f// (extension)
	char 				*info_template; 	///!< additional information i// (nmap def)
	char 				*hostname_template;	///!< hostname how the service call him self h// (nmap def)
	char 				*ostype_template;	///!< os information window linux etc o// (nmap def)
	char 				*devicetype_template;	///!< device type : by example printer or router d// (nmap def)
	_u8				nature;			///!<direct: net application or indirect: content producer software such  as mailer n//
	_u8				type;			///!<defined by the keyword of expresion
	struct s_traffic_software	*next;
} t_traffic_software;


/*!
\struct t_traffic_file
 \brief used to store informations et common used in the file pattern inspection 
 
 used to provide level 7 informations about network stream. Two instance exists in the programm
 on for control packets, the other one for data packet.
 */
 
typedef struct s_traffic_file {

	t_traffic_common		*common;		///!<hold common rules information including protocol
	
	char				*name_template; 	///!< filename n//
	char				*extension_template; 	///!< extension e//
	char				*familly_template; 	///!< familly f//

	char				*additionnal_template;	///!< additionnal  i//
	char				*headers_template; 	///!<headers info h// 
	long				size;			///!< size s//
	long				entropy;		///!< entropy t//
			
	struct s_traffic_file		*next;
} t_traffic_file;



/*!
\struct t_traffic_user
 \brief used to store informations et common used in the user pattern inspection 
 
 used to provide level 7 informations about user information. Two instance exists in the programm
 on for control packets, the other one for data packet.
 */
 
typedef struct s_traffic_user {

	t_traffic_common		*common;		///!<hold common rules information including protocol
	//template
	_u8				nature;			///!< n//	
	char				*familly_template; 	///!< f//
	char				*login_template;   	///!< l//
	char				*pass_template;  	///!< p//
	char				*algorithm_template;	///!<algorithm used to crypt a//
	char				*additionnal_template; 	///!< i//
	char				*hostname_template;	///!< h//
	char				*origin_template;	///!<used to indicate where the user name was found : mail header, instant messae  o//
	struct s_traffic_user		*next;
} t_traffic_user;

/*!
\struct t_traffic_user_to_user
 \brief used to store informations et common used in the user to user relation pattern inspection 
 
 used to provide level 7 informations about inter user relations. Two instance exists in the programm
 on for control packets, the other one for data packet.
 */
 
typedef struct s_traffic_user_to_user {
	t_traffic_common		*common;		///!<hold common rules information including protocol
	//template
	_u8				nature; 		///!< n//
	char				*sender_template; 	///!< s//
	char				*receiver_template;	///!< r//
	char				*familly_template; 	///!< f//
	char				*additionnal_template; 	///!< i//
	char				*origin_template; 	///!< o//
	

	struct s_traffic_user_to_user	*next;
} t_traffic_user_to_user;

#endif
