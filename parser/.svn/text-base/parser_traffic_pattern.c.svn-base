/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"
#include "../headers/pattern_inspection.h"

/*!
 *       \file parser_traffic_pattern.c
 *       \brief Used to parse <trafficPattern> block.
 *
 *	taken inspiration from nmap service probe
 *       \author  Elie
 *       \version 1.1
 *       \date    Dec 2006
 */


t_traffic_rules_nb		rules_nb;

extern 	t_option		option;	
extern	char			parser_current_file[];
//control packets pattern

extern	t_traffic_protocol	*protocol_patterns;
extern	t_traffic_software	*client_patterns;
extern	t_traffic_software	*server_patterns;
extern	t_traffic_file		*file_patterns;
extern	t_traffic_user		*user_patterns; 
extern	t_traffic_user_to_user	*user_to_user_patterns;

//data packets pattern

extern	t_traffic_protocol	*dprotocol_patterns;
extern	t_traffic_software	*dclient_patterns;
extern	t_traffic_software	*dserver_patterns;
extern	t_traffic_file		*dfile_patterns;
extern	t_traffic_user		*duser_patterns; 
extern	t_traffic_user_to_user	*duser_to_user_patterns;

//to add patten in parsed order : lifo
t_traffic_protocol	*lprotocol_patterns;
t_traffic_software	*lclient_patterns;
t_traffic_software	*lserver_patterns;
t_traffic_file		*lfile_patterns;
t_traffic_user		*luser_patterns; 
t_traffic_user_to_user	*luser_to_user_patterns;
t_traffic_protocol	*ldprotocol_patterns;
t_traffic_software	*ldclient_patterns;
t_traffic_software	*ldserver_patterns;
t_traffic_file		*ldfile_patterns;
t_traffic_user		*lduser_patterns; 
t_traffic_user_to_user	*lduser_to_user_patterns;





/*!
 * Parse each line of trafficPattern block 
 * @param matchtext  contain the line to match
 * @param lineno contain the line number for parsing error message
 * @param type	specify the type of pattern to interpret
 * @see parse_traffic_pattern()
 * @return the parsed structure
 * \version 1.1
 * \date    Dec 2006
 * \author Elie
 */

void *parse_traffic_line(char *matchtext, int lineno, int type)
{

	char			*p;
	char 			delimchar, modechar;
	t_traffic_common	*s			= NULL;
	void			*t			= NULL;///!<casted to the type of rule
	int 			pcre_compile_ops 	= 0;
	int			tmpbuflen		= 0;
	int			tmpbuflen2		= 0;
 	const char 		*pcre_errptr 		= NULL;
  	int 			pcre_erroffset 		= 0;
	char 			*tmptemplate		=  NULL;///!<to store template value
	char			*tmpoption_name 	= NULL;///!<used to store option name
	char			*tmpoption_value	= NULL;///!<used to stop option value
	

	//init the common part
	s = (t_traffic_common *)malloc(sizeof(t_traffic_common));
	bzero(s, sizeof(t_traffic_common));

	//adding default confidence
  	if(s->confidence == 0)
		s->confidence = 100; 
		//init the struct
	if(type == PROTOCOL_PATTERN || type == DPROTOCOL_PATTERN) {

		t = (t_traffic_protocol *)malloc(sizeof(t_traffic_protocol));
		bzero(t, sizeof(t_traffic_protocol));
		//attaching the common part
		PROT(t)->common = s;

	} else if(type == CLIENT_PATTERN || type == DCLIENT_PATTERN ||
		  type == SERVER_PATTERN || type == SERVER_PATTERN) {

		t = (t_traffic_software *)malloc(sizeof(t_traffic_software));
		bzero(t, sizeof(t_traffic_software));
		if (type == CLIENT_PATTERN || type == DCLIENT_PATTERN)
			SOFT(t)->type = SOFT_CLIENT;
		else
			SOFT(t)->type = SOFT_SERVER;
				//attaching the common part
		SOFT(t)->common = s;

	} else if(type == FILE_PATTERN || type == DFILE_PATTERN) {

		t = (t_traffic_file *)malloc(sizeof(t_traffic_file));
		 bzero(t, sizeof(t_traffic_file));
		//attaching the common part
		FILE(t)->common = s;

	} else if(type == USER_PATTERN || type == DUSER_PATTERN) {
		
		t = (t_traffic_user *)malloc(sizeof(t_traffic_user));
		bzero(t, sizeof(t_traffic_user));
		//attaching the common part
		USER(t)->common = s;

	} else if(type == USER_TO_USER_PATTERN || type == DUSER_TO_USER_PATTERN) {
		
		t = (t_traffic_user_to_user *)malloc(sizeof(t_traffic_user_to_user));
		bzero(t, sizeof(t_traffic_user_to_user));
		//attaching the common part
		UTOU(t)->common = s;
	}
		
	assert(s->regex_compiled == NULL);	
	// next comes the service name
	p = strchr(matchtext, ' ');
	if (!p) 
		die("%s:%d:\tProtocol name is void line\n", parser_current_file, lineno);
	
	//service name
	s->servicename = (char *) xmalloc((size_t)(p - matchtext + 1));
	memcpy(s->servicename, matchtext, p - matchtext);
	s->servicename[p - matchtext]  = '\0';
	if(option.debug == 43)
		printf("%s:%d: Rule type %d found for protocol : %s\n",parser_current_file, lineno, type, s->servicename);
  matchtext = p;
  while(isspace(*matchtext)) matchtext++;
	// The next part is a perl style regular expression specifier, like:
  // m/^220 .*smtp/i Where 'm' means a normal regular expressions is
  // used, the char after m can be anything (within reason, slash in
  // this case) and tells us what delieates the end of the regex.
  // After the delineating character are any single-character
  // options. ('i' means "case insensitive", 's' means that . matches
  // newlines (both are just as in perl)	
if (*matchtext == 'm') {
    if (!*(matchtext+1))
	    die("%s:%d:\tSignature parsing error matchtext must begin with 'm' :%s", parser_current_file, lineno, matchtext);
    s->matchtype = SERVICEMATCH_REGEX;
    delimchar = *(++matchtext);
    ++matchtext;
    // find the end of the regex
    p = strchr(matchtext, delimchar);
    if (!p) die("%s:%d:\tSignature parsing error could not find end delimiter for regex", parser_current_file, lineno);
    s->matchstrlen = p - matchtext;
    s->matchstr = (char *) xmalloc(s->matchstrlen + 1);
    memcpy(s->matchstr, matchtext, s->matchstrlen);
    s->matchstr[s->matchstrlen]  = '\0';


    matchtext = p + 1; // skip past the delim
	// any options?
    while(*matchtext && !isspace(*matchtext)) {
      	if (*matchtext == 'i')
		s->matchops_ignorecase = 1;
      	else if (*matchtext == 's')
		s->matchops_dotall = 1;
	else if (*matchtext == 'm')
		s->matchops_multi = 1;
      	else 
		die("%s:%d:\tRule illegal regexp option : %c\n", parser_current_file, lineno, *matchtext);
      	matchtext++;
      }
	
		// Next we compile and study the regular expression to match
    if (s->matchops_ignorecase)
      pcre_compile_ops |= PCRE_CASELESS;
		
    if (s->matchops_dotall)
      pcre_compile_ops |= PCRE_DOTALL;
    
    if (s->matchops_multi)
      pcre_compile_ops |= PCRE_MULTILINE;
    
    s->regex_compiled = pcre_compile(s->matchstr, pcre_compile_ops, &pcre_errptr, &pcre_erroffset, NULL);
    if (s->regex_compiled == NULL)
	    die("%s:%d:\tRule parsing illegal regexp (at regexp offset %d): %s\n", parser_current_file, lineno, pcre_erroffset, pcre_errptr);
    if(pcre_errptr != NULL)
    {
	    die("%s:%d:\tSignature regexp compilation failed reason: %s\n", parser_current_file, lineno, pcre_errptr);
    }
    
    // Now study the regexp for greater efficiency
    s->regex_extra = pcre_study(s->regex_compiled, 0, &pcre_errptr);
    if (pcre_errptr != NULL)
		die("%s:%d:\tSignature failed to pcre_study regexp  reason:%s\n", parser_current_file, lineno, pcre_errptr);
} else {
	// Invalid matchtext 
		die("%s:%d:\tSignature incorrect syntax : match string must begin with 'm'\n", parser_current_file, lineno);
}
	
	
	
	/* OK! Now we look at the variable part of the rule */	
while(1) {

    while(isspace(*matchtext)) matchtext++;

    if (*matchtext == '\0' || *matchtext == '\r' || *matchtext == '\n') break;

    modechar = *(matchtext++);
	
    	//rules options ! Let's "snortify"our rules 
	if (modechar == '[')
	{
	//# [bitflows:]
	//# [condidenc:1-100]
	//#  [decoder:string] pass the matching packet to a specific decoder for additionnal interpretation
	//# [depth:1-n] restric the match to the n bytes
	//# [hint:control|data] to provide feedback to the phase detection
	//# [nature:(req|rep|err)] type of the packet. Used for stats
	//# [noreport] does not output the match. Usefull for signature dedicated to statistique or protocol identification.
	//# [offset:1-n] start matching at the N bytes of the payload
	//# [policy:continue|stop] is used to modify the analyzer global matching policy for a given signature.
	//# [priority:-n-n] 
		
		//getting option name
		p = strchr(matchtext, ':');
   		if (!p)
			die("%s:%d:\tSignature error parsing option missing ':'\n", parser_current_file, lineno);
		
		tmpoption_name = NULL;
		tmpbuflen = p - matchtext;
		if (tmpbuflen > 0) {
			tmpoption_name = (char *) xmalloc(tmpbuflen + 1);
			memcpy(tmpoption_name, matchtext, tmpbuflen);
			tmpoption_name[tmpbuflen] = '\0';
		} else  die ("%s:%d:\tSignature error parsing option name is empty\n", parser_current_file, lineno);
		
		if(strchr(tmpoption_name, ']')) // case where [optionnane] [optionmane2:value] the : came from the next option
			die("%s:%d:\tSignature error parsing option missing ':'\n", parser_current_file, lineno);
		
		p = strchr((matchtext + tmpbuflen), ']');
		 if (!p)
			die("%s:%d:\tSignature error parsing option missing ']'\n", parser_current_file, lineno);
				 
		 tmpoption_value = NULL;
		 tmpbuflen2 = p - matchtext - tmpbuflen;
		 if(tmpbuflen2 > 0) {
		 	tmpoption_value = (char *) xmalloc(tmpbuflen2 + 1);
			memcpy(tmpoption_value, (matchtext + tmpbuflen), tmpbuflen2);
			tmpoption_value[tmpbuflen2] = '\0';
		 }
		 
		if(strchr(tmpoption_value, '[')) // case where [optionnane:vale [optionmane2:value] the ] came from the next option
			die("%s:%d:\tSignature error parsing option missing ']'\n", parser_current_file, lineno);
		 
		tmpoption_value++; ///!\todo dirty hack to remove ':' need to be reworked
		//die("parsed option = %s with value %s\n", tmpoption_name, tmpoption_value);
		matchtext += tmpbuflen;
		matchtext += tmpbuflen2 + 1;
		//printf("matchtext is now %s\n", matchtext);
		//modechar = *(matchtext++);
		
		switch (*tmpoption_name) {
			case 'b':
				if(strcasecmp(tmpoption_name, "bitflows") == 0)
				{
					warning("%s:%d:\tbitflows does not work yet\n", parser_current_file, lineno);
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'c':
				if(strcasecmp(tmpoption_name, "confidence") == 0)
				{
					s->confidence = atoi(tmpoption_value); 
	    				if (s->confidence < 1 || s->confidence > 100)
		    				die("%s:%d:\tConfidence needs to be between 1 and 100\n", parser_current_file, lineno);	
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'd':
				if(strcasecmp(tmpoption_name, "depth") == 0)
				{
					s->depth = atoi(tmpoption_value); 
	    				if (s->depth < 1)
		    				die("%s:%d:\tDepth needs to be > 1\n", parser_current_file, lineno);
				} else if(strcasecmp(tmpoption_name, "decoder") == 0)
				{
					///!\todo implements it 
					// s->modules
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'h':
				if(strcasecmp(tmpoption_name, "hint") == 0)
				{
					if(strcasecmp(matchtext, "control") == 0) {
						s->next_phase = CONTROL_PHASE;
					} else	if(strcasecmp(matchtext, "data") == 0) {
		    				s->next_phase = DATA_PHASE;
					} else
					die("%s:%d:\thint needs to be control/data\n", parser_current_file, lineno);	
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'n':
				if(strcasecmp(tmpoption_name, "nature") == 0)
				{
					if(strcasecmp(matchtext, "rep") == 0) {
		    				s->type = GROUP_REP;
					} else if(strcasecmp(matchtext, "req") == 0) {
		    				s->type = GROUP_REQ;
					} else	if(strcasecmp(matchtext, "err") == 0) {
		    				s->type = GROUP_ERR;
					} else
					die("%s:%d:\tnature needs to be either rep/req/err\n", parser_current_file, lineno);
				} else if(strcasecmp(tmpoption_name, "noreport") == 0)
				{
					s->noreport = 1;
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'o':
				if(strcasecmp(tmpoption_name, "offset") == 0)
				{
					s->offset = atoi(tmpoption_value); 
	    				if (s->offset < 1)
		    				die("%s:%d:\toffset needs to be > 1\n", parser_current_file, lineno);
				} else								
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;
			case 'p':
				if(strcasecmp(tmpoption_name, "policy") == 0)
				{
					if (strcasecmp(tmpoption_value, "continue"))
					{
						s->policy = RULE_POLICY_CONTINUE;
					
					} else if (strcasecmp(tmpoption_value, "stop"))
					{	
						s->policy = RULE_POLICY_STOP;
					
					} else
					die("%s:%d:\tSignature Policy invalid value %s\n", parser_current_file, lineno, tmpoption_value);
				} else if(strcasecmp(tmpoption_name, "priority") == 0){
					s->priority = atoi(tmpoption_value); 
	    				if (s->priority != 0)
		    				die("%s:%d:\tPriority needs to be > 1\n", parser_current_file, lineno);
				} else
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, tmpoption_name);
				break;				
			default:
				die("%s:%d:\tSignature invalid option %s\n", parser_current_file, lineno, matchtext);
		}
		//cleaning 
		free(tmpoption_name);
		if(tmpoption_value)
			free(tmpoption_value - 1);
		continue;
	}
     
    //let's do template 
    if (*matchtext == 0 || *matchtext == '\r' || *matchtext == '\n')
	    die("%s:%d:\tRule parsing: trunked rule\n", parser_current_file, lineno);
		


    delimchar = *(matchtext++);
    p = strchr(matchtext, delimchar);
    if (!p) die("%s:%d:\tSignature syntax erorr can't find ending delimiter: %c\n", parser_current_file, lineno, modechar);
		
    tmptemplate = NULL;
    tmpbuflen = p - matchtext;
    if (tmpbuflen > 0) {
      tmptemplate = (char *) xmalloc(tmpbuflen + 1);
      memcpy(tmptemplate, matchtext, tmpbuflen);
      tmptemplate[tmpbuflen] = '\0';
    }


    ///\warning it either A or E because it can't be an event and an error at the same time 
    if (modechar == 'A') { 
	    if(s->event_name != NULL)
		    die("%s:%d:\tSignature can't be an Alert and an Event at the same type. Flags E and A where use at the same time\n", parser_current_file, lineno); 
	    s->event_name =  tmptemplate; 
	    s->event_type = TYPE_ERROR; 
	    matchtext = p + 1;
	    continue;
    }
            
    if (modechar == 'E') { 
	    if(s->event_name != NULL)
		    die("%s:%d:\tSignature can't be an Alert and an Event at the same type. Flags E and A where use at the same time\n", parser_current_file, lineno); 
	    s->event_name =  tmptemplate; 
	    s->event_type = TYPE_EVENT; 
	    matchtext = p + 1;
	    continue;
    }

    
    //EVENT
    if (modechar == 'C') { s->class_shortname = tmptemplate; 	matchtext = p + 1; continue;} //classification shortname
    if (modechar == 'N') { s->event_nature    =  tmptemplate; 	matchtext = p + 1; continue;}		//nature
    if (modechar == 'D') { s->event_details   =  tmptemplate; 	matchtext = p + 1; continue;}	//details
    if (modechar == 'T') { s->event_target    =  tmptemplate; 	matchtext = p + 1; continue;}	//target


    
    
    //printf("TYPE = %d modchar = %c template %s\n", type, modechar, tmptemplate);
    //oh boy that is so ugly, i do hate parser
    if(type == PROTOCOL_PATTERN || type == DPROTOCOL_PATTERN) {
		     if (modechar == 'v') PROT(t)->version_template = tmptemplate;
		else if (modechar == 'f') PROT(t)->familly_template = tmptemplate;
		else if (modechar == 'i') PROT(t)->additionnal_template = tmptemplate;
		else if (modechar == 'c') PROT(t)->encrypted_template = tmptemplate;
		else die("%s:%d:\tProtocol signature parsing error: unrecognized template '%c'\n", parser_current_file, lineno, modechar);
    		
    } else if(type == CLIENT_PATTERN || type == DCLIENT_PATTERN || type == SERVER_PATTERN || type == SERVER_PATTERN) {
		     
		     if (modechar == 'p') SOFT(t)->product_template = tmptemplate;
		else if (modechar == 'v') SOFT(t)->version_template = tmptemplate;
		else if (modechar == 'f') SOFT(t)->familly_template = tmptemplate;
		else if (modechar == 'i') SOFT(t)->info_template = tmptemplate;
		else if (modechar == 'h') SOFT(t)->hostname_template = tmptemplate;
		else if (modechar == 'o') SOFT(t)->ostype_template = tmptemplate;
		else if (modechar == 'd') SOFT(t)->devicetype_template = tmptemplate;
		else if (modechar == 'n') SOFT(t)->nature =  (strncasecmp(tmptemplate, "indirect", 8) == 0) ? SOFT_INDIRECT : SOFT_DIRECT;
		else die("%s:%d:\tSoftware signature parsing error: unrecognized template '%c'\n", parser_current_file, lineno, modechar);

	} else if(type == FILE_PATTERN || type == DFILE_PATTERN) {
		     
		     if (modechar == 'n') FILE(t)->name_template = tmptemplate;
		else if (modechar == 'e') FILE(t)->extension_template = tmptemplate;
		else if (modechar == 'f') FILE(t)->familly_template = tmptemplate;
		else if (modechar == 'i') FILE(t)->additionnal_template = tmptemplate;
		else if (modechar == 'h') FILE(t)->headers_template = tmptemplate;
		else if (modechar == 's') FILE(t)->size = strtol(tmptemplate, (char **)NULL, 10);
		else if (modechar == 't') FILE(t)->entropy = strtol(tmptemplate, (char **)NULL, 10);
		else die("%s:%d:\tFile signature parsing error: unrecognized template '%c'\n", parser_current_file, lineno, modechar);


		//additional type cast check
		/*
		if ((errno == ERANGE && (FILE(t)->size == LONG_MAX || FILE(t)->size == LONG_MIN)) || (errno != 0 && FILE(t)->size == 0)) {
               	perror("strtol");
               	die("Size Please modify the rule at line %d template '%c'", lineno, modechar);
               }

		if ((errno == ERANGE && (FILE(t)->entropy == LONG_MAX || FILE(t)->entropy == LONG_MIN)) || (errno != 0 && FILE(t)->entropy == 0)) {
               	perror("strtol");
               	die(" Entropy Please modify the rule at line %d template '%c'", lineno, modechar);
	}*/
	} else if(type == USER_PATTERN || type == DUSER_PATTERN) {

		     if (modechar == 'f') USER(t)->familly_template = tmptemplate;
		else if (modechar == 'l') USER(t)->login_template = tmptemplate;
		else if (modechar == 'p') USER(t)->pass_template = tmptemplate;
		else if (modechar == 'a') USER(t)->algorithm_template = tmptemplate;
		else if (modechar == 'i') USER(t)->additionnal_template = tmptemplate;
		else if (modechar == 'h') USER(t)->hostname_template = tmptemplate;
		else if (modechar == 'o') USER(t)->origin_template = tmptemplate;
		else if (modechar == 'n') USER(t)->nature = (strncasecmp(tmptemplate, "indirect", 8) == 0) ? RELATION_INDIRECT : RELATION_DIRECT;
		else die("%s:%d:\tUser signature parsing error: unrecognized template '%c'\n", parser_current_file, lineno, modechar);
 
	} else if(type == USER_TO_USER_PATTERN || type == DUSER_TO_USER_PATTERN) {
	
		     if (modechar == 'n')  UTOU(t)->nature = (strncasecmp(tmptemplate, "indirect", 8) == 0) ? RELATION_INDIRECT : RELATION_DIRECT;
		else if (modechar == 's')  UTOU(t)->sender_template = tmptemplate;
		else if (modechar == 'r')  UTOU(t)->receiver_template = tmptemplate;
		else if (modechar == 'f')  UTOU(t)->familly_template = tmptemplate;
		else if (modechar == 'i')  UTOU(t)->additionnal_template = tmptemplate;
		else if (modechar == 'o')  UTOU(t)->origin_template = tmptemplate;
		else die("%s:%d:\tUser relation signature parsing error: unrecognized template '%c'\n", parser_current_file, lineno, modechar);
	} else
		die("%s:%d:\tThere is something wrong in rule parser type %d does not exist",parser_current_file, lineno, type);

    matchtext = p + 1;
  }	

	if(option.debug == 43)
		printf("%s:%d:\tRule type %d successfully parsed: %s\n",parser_current_file, lineno, type, s->servicename);
	return t;
}


/*!
 * Adding rules to the correct list 
 * @void *t the parsed rule
 * @int type the type of rule: user, protocol ..
 * @int l line number + 1
 * @see parse_traffic pattern()
 * @return nothing
 * \version 1.1
 * \date    Dec 2006
 * \author Elie
 */

void add_pattern(void *t, int type, int l)
{
	assert(t != NULL && type != 0);
	l--;
	switch(type)
	{
		case PROTOCOL_PATTERN:
			assert(PROT(t)->common != NULL);
			assert(PROT(t)->common->servicename != NULL);
			assert(PROT(t)->familly_template != NULL);
			
			//type check
			if (!(PROT(t)->familly_template)) 
				die("Protocol Rule invalid: Familly not specified for protocol %s@%d\n",PROT(t)->common->servicename, l);
			
			if(protocol_patterns == NULL)
				protocol_patterns = PROT(t);
			else
				lprotocol_patterns->next = PROT(t);
			lprotocol_patterns = PROT(t);
			break; 
		case DPROTOCOL_PATTERN:
			//type check
			if (!PROT(t)->familly_template) 
				die("Protocol Rule invalid: Familly not specified for protocol %s@%d\n",PROT(t)->common->servicename, l);
			
			
			if(dprotocol_patterns == NULL)
				dprotocol_patterns = PROT(t);
			else
				ldprotocol_patterns->next = PROT(t);
			ldprotocol_patterns = PROT(t); 
			break;
		case CLIENT_PATTERN:
			//type check
			if (!SOFT(t)->product_template) die("Client Rule invalid: Soft name not specified @%d use p// template\n",l);
			if (!SOFT(t)->familly_template) die("Client Rule invalid: Familly not specified for soft %s@%d add f// template\n",SOFT(t)->product_template, l);
			
			
			if(client_patterns == NULL)
				client_patterns = SOFT(t);
			else
				lclient_patterns->next = SOFT(t);
			lclient_patterns = SOFT(t);
			break;
		case DCLIENT_PATTERN:
			
			//type check
			if (!SOFT(t)->product_template) die("Client Rule invalid: Soft name not specified @%d use p// template\n",l);
			if (!SOFT(t)->familly_template) die("Client Rule invalid: Familly not specified for soft %s@%d add f// template\n",SOFT(t)->product_template, l);
		
			
			if(dclient_patterns == NULL)
				dclient_patterns = SOFT(t);
			else
				ldclient_patterns->next = SOFT(t);
			ldclient_patterns = SOFT(t);
			break;
		case SERVER_PATTERN:
			
			//if (!SOFT(t)->product_template) die("%s:%d:\tdServer Rule %s error: Soft product not specified use p// template\n",parser_current_file, l, SOFT(t)->common->servicename);

			if(server_patterns == NULL)
				server_patterns = SOFT(t);
			else
				lserver_patterns->next = SOFT(t);
			lserver_patterns = SOFT(t);
			break;
		case DSERVER_PATTERN:
			
			if (!SOFT(t)->product_template) die("Server Rule invalid: Soft name not specified @%d use p// template\n",l);
			
			if(dserver_patterns == NULL)
				dserver_patterns = SOFT(t);
			else
				ldserver_patterns->next = SOFT(t);
			ldserver_patterns = SOFT(t);
			break;
		case FILE_PATTERN:
			if(file_patterns == NULL)
				file_patterns = FILE(t);
			else
				lfile_patterns->next = FILE(t);
			lfile_patterns = FILE(t);
			break;
		case DFILE_PATTERN:
			if (!FILE(t)->extension_template) die("File Rule invalid: extension not specified for %s@%d add e// template\n",FILE(t)->familly_template, l);
			if (!FILE(t)->familly_template) die("File Rule invalid: Familly not specified for %s@%d add f// template\n",FILE(t)->extension_template, l);

			if(dfile_patterns == NULL)
				dfile_patterns = FILE(t);
			else
				ldfile_patterns->next = FILE(t);
			ldfile_patterns = FILE(t);
			break;
		case USER_PATTERN:
			if (!USER(t)->login_template) die("User Rule invalid: login not specified for %s@%d add l// template\n",USER(t)->common->servicename, l);
			if (!USER(t)->familly_template) die("User Rule invalid: Familly not specified for %s@%d add f// template\n",USER(t)->common->servicename, l);

			if(user_patterns == NULL)
				user_patterns = USER(t);
			else
				luser_patterns->next = USER(t);
			luser_patterns = USER(t);
			break;
		case DUSER_PATTERN:
			if (!USER(t)->login_template) die("User Rule invalid: login not specified for %s@%d add l// template\n",USER(t)->common->servicename, l);
			if (!USER(t)->familly_template) die("User Rule invalid: Familly not specified for %s@%d add f// template\n",USER(t)->common->servicename, l);

			
			if(duser_patterns == NULL)
				duser_patterns = USER(t);
			else
				lduser_patterns->next = USER(t);
			lduser_patterns = USER(t);
			break;
		case USER_TO_USER_PATTERN:
			
			if (!UTOU(t)->sender_template) die("User relation Rule invalid: sender not specified for %s@%d add s// template\n",UTOU(t)->common->servicename, l);
			if (!UTOU(t)->receiver_template) die("User relation Rule invalid: receiver not specified for %s@%d add r// template\n",UTOU(t)->common->servicename, l);
			if (!UTOU(t)->familly_template) die("User Rule invalid: Familly not specified for %s@%d add f// template\n",UTOU(t)->common->servicename, l);

			if(user_to_user_patterns == NULL)
				user_to_user_patterns = UTOU(t);
			else
				luser_to_user_patterns->next = UTOU(t);
			luser_to_user_patterns = UTOU(t);
			break;
		case DUSER_TO_USER_PATTERN:
			
			if (!UTOU(t)->sender_template) die("User relation Rule invalid: sender not specified for %s@%d add s// template\n",UTOU(t)->common->servicename, l);
			if (!UTOU(t)->receiver_template) die("User relation Rule invalid: receiver not specified for %s@%d add r// template\n",UTOU(t)->common->servicename, l);
			if (!UTOU(t)->familly_template) die("User Rule invalid: Familly not specified for %s@%d add f// template\n",UTOU(t)->common->servicename, l);

			if(duser_to_user_patterns == NULL)
				duser_to_user_patterns = UTOU(t);
			else
				lduser_to_user_patterns->next = UTOU(t);
			lduser_to_user_patterns = UTOU(t);
			break;
		default:
			die("Error adding rule type unknown %d\n", type);
			break;
	}
		return;
}

/*!
 * Parsing trafficPattern block 
 * @param fp  the file pointer to parse
 * @param l the line in the conf
 * @see parse_conf()
 * @return when block is over
 * \note parsing is ugly, so ugly
 * \version 1.1
 * \date    Dec 2006
 * \author Elie
 */

int parse_traffic_pattern(FILE *fp, int l)
{
	char 			line[4096], *matchtext;
	_u32	count = 0;
	bzero(line,sizeof(line));
	while ((fgets(line, sizeof(line), fp)))
	{
		l++;
		if (!(strncmp(line,"</trafficPattern>",11)))
		{
			if (option.debug == 42)
				printf("Traffic pattern block parsing finish : %d pattern found\n", count);
			return 1;
		}
		//comment
		if (parse_is_comment(line))
			continue;
		//let's do parse a la nmap
		matchtext = line;
		if (strncmp(matchtext, "pcmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, PROTOCOL_PATTERN), PROTOCOL_PATTERN, l);
			rules_nb.pcount++;
		} else if (strncmp(matchtext, "pdmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DPROTOCOL_PATTERN), DPROTOCOL_PATTERN, l);
			rules_nb.pcount++;
		} else if (strncmp(matchtext, "ccmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, CLIENT_PATTERN), CLIENT_PATTERN, l);
			rules_nb.ccount++;
		} else if (strncmp(matchtext, "cdmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DCLIENT_PATTERN), DCLIENT_PATTERN, l);
			rules_nb.ccount++;
		} else if (strncmp(matchtext, "scmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, SERVER_PATTERN), SERVER_PATTERN, l);
			rules_nb.scount++;
		} else if (strncmp(matchtext, "sdmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DSERVER_PATTERN), DSERVER_PATTERN, l);
			rules_nb.scount++;
		} else if (strncmp(matchtext, "fcmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, FILE_PATTERN), FILE_PATTERN, l);
			rules_nb.fcount++;
		} else if (strncmp(matchtext, "fdmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DFILE_PATTERN), DFILE_PATTERN, l);
			rules_nb.fcount++;
		} else if (strncmp(matchtext, "ecmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, EVENT_PATTERN), EVENT_PATTERN, l);
			rules_nb.ecount++;
		} else if (strncmp(matchtext, "edmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DEVENT_PATTERN), DEVENT_PATTERN, l);
			rules_nb.ecount++;
		} else if (strncmp(matchtext, "ucmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, USER_PATTERN), USER_PATTERN, l);
			rules_nb.ucount++;
		} else if (strncmp(matchtext, "udmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DUSER_PATTERN), DUSER_PATTERN, l);
			rules_nb.ucount++;
		} else if (strncmp(matchtext, "rcmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, USER_TO_USER_PATTERN), USER_TO_USER_PATTERN, l);
			rules_nb.rcount++;
		} else if (strncmp(matchtext, "rdmatch ", 8) == 0) {
			matchtext += 8;
			add_pattern(parse_traffic_line(matchtext, l, DUSER_TO_USER_PATTERN),DUSER_TO_USER_PATTERN, l);
			rules_nb.rcount++;
		} else 
			die("%s:%d:\tRules parsing syntax error:unknown rule type:%s\n",parser_current_file, l, matchtext);
		
		bzero(line,sizeof(line));
	}

	return 1;
}




