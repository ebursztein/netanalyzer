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
 *       \file traffic_pattern_function.c
 *       \brief set of functions used for signature engine.
 *	 matching functions and hook to structures are here
 *
 *	 Inspiration by pof, NMap, l7 filter and passive vulnerability scanner.
 *       \author  Elie
 *       \version 1.4
 *       \date    May 2007
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>
#include<assert.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"
#include "headers/pattern_inspection.h"


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


extern  t_traffic_rules_nb	rules_nb;
extern 	t_option		option;	
extern	t_analyze		analyze;
extern	t_tuning		tuning;
extern 	t_mutex			mutex;

int need_to_return(_u8 rule_policy); 

///!\todo to remove

/*
	
	t_traffic_pattern	*traffic_patterns;///!<server side traffic pattern
	t_traffic_pattern	*client_traffic_patterns;///!<client side traffic pattern
	t_traffic_pattern	*protocol_traffic_patterns;///!<protocol detection pattern
	t_traffic_pattern	*file_traffic_patterns;///!<file information detection pattern
	int			nb_traffic_patterns;		
*/
#define SUBSTARGS_MAX_ARGS 5
#define SUBSTARGS_STRLEN 128
#define SUBSTARGS_ARGTYPE_NONE 0
#define SUBSTARGS_ARGTYPE_STRING 1
#define SUBSTARGS_ARGTYPE_INT 2

///!\todo fixeme declaration
//generic function to match against various list
//void traffic_pattern_match(char * payload, int buflen, _u32 ip, _u16 port, _s32 proto, t_traffic_pattern *traf, _u8 type, t_session *s);


struct substargs {
	int num_args; // Total number of arguments found
	char str_args[SUBSTARGS_MAX_ARGS][SUBSTARGS_STRLEN];
  // This is the length of each string arg, since they can contain zeros.
  // The str_args[] are zero-terminated for convenience in the cases where
  // you know they won't contain zero.
	int str_args_len[SUBSTARGS_MAX_ARGS]; 
	int int_args[SUBSTARGS_MAX_ARGS];
  // The type of each argument -- see #define's above.
	int arg_types[SUBSTARGS_MAX_ARGS];
};
	
	
// This simple function parses arguments out of a string.  The string
// starts with the first argument.  Each argument can be a string or
// an integer.  Strings must be enclosed in double quotes ("").  Most
// standard C-style escapes are supported.  If this is successful, the
// number of args found is returned, args is filled appropriately, and
// args_end (if non-null) is set to the character after the closing
// ')'.  Otherwise we return -1 and the values of args and args_end
// are undefined.
static int getsubstcommandargs(struct substargs *args, char *args_start, 
			       char **args_end) {
	char *p;
	unsigned int len;
	if (!args || !args_start) return -1;

	memset(args, 0, sizeof(*args));

	while(*args_start && *args_start != ')') {
    // Find the next argument.
		while(isspace(*args_start)) args_start++;
		if (*args_start == ')')
			break;
		else if (*args_start == '"') {
      // OK - it is a string
      // Do we have space for another arg?
			if (args->num_args == SUBSTARGS_MAX_ARGS)
				return -1;
			do {
				args_start++;
				if (*args_start == '"' && (*(args_start - 1) != '\\' || *(args_start - 2) == '\\'))
					break;
				len = args->str_args_len[args->num_args];
				if (len >= SUBSTARGS_STRLEN - 1)
					return -1;
				args->str_args[args->num_args][len] = *args_start;
				args->str_args_len[args->num_args]++;
			} while(*args_start);
			len = args->str_args_len[args->num_args];
			args->str_args[args->num_args][len] = '\0';
      // Now handle escaped characters and such
			if (!cstring_unescape(args->str_args[args->num_args], &len))
				return -1;
			args->str_args_len[args->num_args] = len;
			args->arg_types[args->num_args] = SUBSTARGS_ARGTYPE_STRING;
			args->num_args++;
			args_start++;
			args_start = strpbrk(args_start, ",)");
			if (!args_start) return -1;
			if (*args_start == ',') args_start++;
		} else {
      // Must be an integer argument
			args->int_args[args->num_args] = (int) strtol(args_start, &p, 0);
			if (p <= args_start) return -1;
			args_start = p;
			args->arg_types[args->num_args] = SUBSTARGS_ARGTYPE_INT;
			args->num_args++;
			args_start = strpbrk(args_start, ",)");
			if (!args_start) return -1;
			if (*args_start == ',') args_start++;
		}
	}

	if (*args_start == ')') args_start++;
	if (args_end) *args_end = args_start;
	return args->num_args;
}
// This function does the actual substitution of a placeholder like $2
// or $U(4) into the given buffer.  It returns the number of chars
// written, or -1 if it fails.  tmplvar is a template variable, such
// as "$U(2)".  We determine the appropriate string representing that,
// and place it in newstr (as long as it doesn't exceed newstrlen).
// We then set *tmplvarend to the character after the
// variable. subject, subjectlen, ovector, and nummatches mean the
// same as in dotmplsubst().
static int substvar(char *tmplvar, char **tmplvarend, char *newstr, 
		int newstrlen, const char *subject, int subjectlen, int *ovector,
		int nummatches) 
{
	char substcommand[16];
	char *p = NULL;
	char *p_end;
	int len;
	int subnum = 0;
	int offstart, offend;
	int byteswritten = 0; // for return val
	int rc;
	int i;
	struct substargs command_args;
  	// skip the '$'
	if (*tmplvar != '$') return -1;
	tmplvar++;

	if (!isdigit(*tmplvar)) {
		p = strchr(tmplvar, '(');
		if (!p) return -1;
		len = p - tmplvar;
		if (!len || len >= (int) sizeof(substcommand))
			return -1;
		memcpy(substcommand, tmplvar, len);
		substcommand[len] = '\0';
		tmplvar = p+1;
    // Now we grab the arguments.
		rc = getsubstcommandargs(&command_args, tmplvar, &p_end);
		if (rc <= 0) return -1;
		tmplvar = p_end;
	} else {
		substcommand[0] = '\0';
		subnum = *tmplvar - '0';
		tmplvar++;
	}

	if (tmplvarend) *tmplvarend = tmplvar;

	if (!*substcommand) {
		if (subnum > 9 || subnum <= 0) return -1;
		if (subnum >= nummatches) return -1;
		offstart = ovector[subnum * 2];
		offend = ovector[subnum * 2 + 1];
		assert(offstart >= 0 && offstart < subjectlen);
		assert(offend >= 0 && offend <= subjectlen);
		len = offend - offstart;
    // A plain-jane copy
	if (newstrlen <= len - 1)
		return -1;
	memcpy(newstr, subject + offstart, len);
	byteswritten = len;
	} else if (strcmp(substcommand, "P") == 0) {
		if (command_args.arg_types[0] != SUBSTARGS_ARGTYPE_INT)
			return -1;
	subnum = command_args.int_args[0];
	if (subnum > 9 || subnum <= 0) return -1;
	if (subnum >= nummatches) return -1;
	offstart = ovector[subnum * 2];
	offend = ovector[subnum * 2 + 1];
	assert(offstart >= 0 && offstart < subjectlen);
	assert(offend >= 0 && offend <= subjectlen);
    // This filter only includes printable characters.  It is particularly
    // useful for collapsing unicode text that looks like 
    // "W\0O\0R\0K\0G\0R\0O\0U\0P\0"
		for(i=offstart; i < offend; i++)
			if (isprint((int) subject[i])) {
			if (byteswritten >= newstrlen - 1)
				return -1;
			newstr[byteswritten++] = subject[i];
			}
	} else if (strcmp(substcommand, "SUBST") == 0) {
		char *findstr, *replstr;
		int findstrlen, replstrlen;
		if (command_args.arg_types[0] != SUBSTARGS_ARGTYPE_INT)
			return -1;
		subnum = command_args.int_args[0];
		if (subnum > 9 || subnum <= 0) return -1;
		if (subnum >= nummatches) return -1;
		offstart = ovector[subnum * 2];
		offend = ovector[subnum * 2 + 1];
		assert(offstart >= 0 && offstart < subjectlen);
		assert(offend >= 0 && offend <= subjectlen);
		if (command_args.arg_types[1] != SUBSTARGS_ARGTYPE_STRING ||
					command_args.arg_types[2] != SUBSTARGS_ARGTYPE_STRING)
			return -1;
		findstr = command_args.str_args[1];
		findstrlen = command_args.str_args_len[1];
		replstr = command_args.str_args[2];
		replstrlen = command_args.str_args_len[2];
		for(i=offstart; i < offend; ) {
			if (byteswritten >= newstrlen - 1)
				return -1;
			if (offend - i < findstrlen)
				newstr[byteswritten++] = subject[i++]; // No room for match
			else if (memcmp(subject + i, findstr, findstrlen) != 0)
				newstr[byteswritten++] = subject[i++]; // no match
			else {
	// The find string was found, copy it to newstring
				if (newstrlen - 1 - byteswritten < replstrlen)
					return -1;
				memcpy(newstr + byteswritten, replstr, replstrlen);
				byteswritten += replstrlen;
				i += findstrlen;
			}
		}
	} else return -1; // Unknown command

	if (byteswritten >= newstrlen) return -1;
	newstr[byteswritten] = '\0';
	return byteswritten;
}
	
// This function takes a template string (tmpl) which can have
// placeholders in it such as $1 for substring matches in a regexp
// that was run against subject, and subjectlen, with the 'nummatches'
// matches in ovector.  The NUL-terminated newly composted string is
// placed into 'newstr', as long as it doesn't exceed 'newstrlen'
// bytes.  Trailing whitespace and commas are removed.  Returns zero for success
static int dotmplsubst(const char *subject, int subjectlen, 
		int *ovector, int nummatches, char *tmpl, char *newstr,
		int newstrlen) {
	int newlen;
	char *srcstart=tmpl, *srcend;
	char *dst = newstr;
	char *newstrend = newstr + newstrlen; // Right after the final char
	
	if (!newstr || !tmpl) return -1;
	if(newstrlen < 3) return -1; 

	while(*srcstart) {
		// First do any literal text before '$'
		srcend = strchr(srcstart, '$');
		if (!srcend) {
			// Only literal text remain!
			while(*srcstart) {
				if (dst >= newstrend - 1)
					return -1;
				*dst++ = *srcstart++;
			}
			*dst = '\0';
			while (--dst >= newstr) {
				if (isspace(*dst) || *dst == ',') 
					*dst = '\0';
				else break;
			}
			return 0;
		} else {
			// Copy the literal text up to the '$', then do the substitution
			newlen = srcend - srcstart;
			if (newlen > 0) {
				if (newstrend - dst <= newlen - 1)
					return -1;
				memcpy(dst, srcstart, newlen);
				dst += newlen;
			}
			srcstart = srcend;
			newlen = substvar(srcstart, &srcend, dst, newstrend - dst, subject, subjectlen, ovector, nummatches);
			if (newlen == -1) 
				return -1;
			dst += newlen;
			srcstart = srcend;
			}
		}

	if (dst >= newstrend - 1)
		return -1;
	*dst = '\0';
	while (--dst >= newstr) {
		if (isspace(*dst) || *dst == ',') 
			*dst = '\0';
		else break;
	}
	return 0;
}

int getVersionStr(int torewrite)
{
 	return 0;
}


/*!
 * used to decide according to signature policy and global policy if the match function need to return
 * First it apply signature policy if found then it look at global
 * @param rule_policy the rule policy value
 * @return 1 if need to return 0 if need to continue
 * \version 1.1
 * \date    Feb 2007
 * \author Elie
 */
int need_to_return(_u8 rule_policy) {
	     if (rule_policy == RULE_POLICY_STOP) return 1;
	else if (rule_policy == RULE_POLICY_CONTINUE) return 0;
	else if(tuning.patternsignaturemultimatch != 0) return 0;
	else return 1;
}

void analyze_traffic_pattern(t_session *s, t_pkt *p)
{
	_u32 nbpkt = 0;
	assert(s != NULL && p != NULL);
	//assert (p->pkt_proto > 0 && s->proto > 0);	
	//assert(p->payload_len > 0);
	//assert(p->ip);
	//ensuring that the sa is not doing stupid things
	//assert(p->phase_client == CONTROL_PHASE || p->phase_client == DATA_PHASE || p->phase_server == JAM_PHASE);
			//(s->src == 0 || s->dst == 0));
	/*if (!(p->phase_client == CONTROL_PHASE || p->phase_client == DATA_PHASE || (s->src == 0 || s->dst == 0)))
	*/
	assert(p->phase_client == CONTROL_PHASE || p->phase_client == DATA_PHASE || p->phase_server == JAM_PHASE);
	/*{
			session_display_plain(s);
			die("phase:%d:src:%d:dst:%d\n",p->phase_client, s->src, s->dst);
	}*/
	assert(p->phase_server == CONTROL_PHASE || p->phase_server == DATA_PHASE || p->phase_server == JAM_PHASE);
			//|| (s->src == 0 || s->dst == 0));
	
	if (p->payload_len == 0 || p->ip == 0)
		return;

	if(tuning.nbpktinit)
	{
		if (s->proto >= TCP)
			nbpkt = tuning.nbpktinit + 3;
	} else {
		nbpkt = tuning.nbpktinit;
	}
	
	if(option.debug == 50)
		printf("Packet no:%d, len:%d payload|%s|\n",s->nb_pkt_in + s->nb_pkt_out, p->payload_len, p->payload);
	//init phase optim ? yes ? so do we do inspection ?
	if(tuning.nbpktinit && tuning.nbpktinit <  s->nb_pkt_in + s->nb_pkt_out)
		return;
	
	if(option.debug == 51)
		printf("Packet no:%d, len:%d payload|%s|\n",s->nb_pkt_in + s->nb_pkt_out, p->payload_len, p->payload);
	
	//do we use directional information ? ensure that we are not in cold start ...
	if(tuning.usedirectionnal && s->state != SESS_PARTIAL_TCP)
	{
		//client
		if(p->ip->src == s->src)
		{
			if (tuning.useclientpattern  && (analyze.session || analyze.software || analyze.error || analyze.event))
				traffic_pattern_match_packet_software(s,p, SOFT_CLIENT);
		} else {
			if (tuning.useserverpattern  && (analyze.session || analyze.software || analyze.error || analyze.event))
				traffic_pattern_match_packet_software(s,p, SOFT_SERVER);
		} 
	} else {
		if (tuning.useclientpattern && (analyze.session || analyze.software || analyze.error || analyze.event))
			traffic_pattern_match_packet_software(s, p, SOFT_CLIENT);
		if (tuning.useserverpattern && (analyze.session || analyze.software || analyze.error || analyze.event))
			traffic_pattern_match_packet_software(s, p, SOFT_SERVER);
	}
	//both side
	if (tuning.usetrafficpattern && (analyze.session || analyze.error || analyze.event))
		traffic_pattern_match_packet_protocol(s, p);
	if (tuning.usefilepattern && (analyze.session || analyze.error || analyze.event))
		traffic_pattern_match_packet_file(s, p);
	if (tuning.useuserpattern && (analyze.user || analyze.error || analyze.event))
		traffic_pattern_match_packet_user(s, p);
	if (tuning.useu2upattern && (analyze.user || analyze.error || analyze.event))
		traffic_pattern_match_packet_user2user(s, p);
}

void traffic_pattern_match_packet_file(t_session *s, t_pkt *p)
{
	
	_u16 			buflen = 0;
	int 	buflen_base		= 0; 		///!<used to keep buflen  befors rule alteration
	_s16 			rc, nummatch, i = 0;
	char 	 		*bufc = p->payload;
	char			*buf = p->payload;
	t_traffic_file 		*t = NULL;
	t_file			*file = NULL;
	_s32 			ovector[150]; ///!<allows 50 substring matches (including the overall match)	
	_u8 			phase;
	_u8			stream;
	
	//add check here
	assert(s);
	assert(p);
	//assert(s->proto > 0);
	//assert(p->payload_len);

	//tuning inspection size 
	if (tuning.patternrestrictlen && p->payload_len > tuning.patternrestrictlen)
		buflen = tuning.patternrestrictlen;
	else
		buflen = p->payload_len;
	
	
	//saving original size
	buflen_base = buflen;
	
	
	//we are client style : ip src, port dst
	if(option.debug == 21)
		printf("doing file pattern matching on session %lld pkt %d for len %d\n", s->id, s->nb_pkt_in + s->nb_pkt_out, buflen);
	
	//use the phase detection luke
	if(p->ip->src == s->src)
	{
		stream = HOST_FROM;
		if (p->phase_client == CONTROL_PHASE)
		{
			t = file_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_client == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= dfile_patterns;
			phase = DATA_PHASE;
		}
	} else {
		stream = HOST_TO;
		if (p->phase_server == CONTROL_PHASE) {
			t = file_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_server == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= dfile_patterns;
			phase = DATA_PHASE;
		}
	}
	
				
	while (t != NULL)
	{
		assert(t->common);
		assert(t->common->regex_compiled);
		i++;
		
		//restoring
		bufc 	= p->payload;
		buf 	= p->payload;
		buflen	= buflen_base;
		//pattern restriction according to rules options 
		//start offset
		if((t->common->offset <= buflen) && (t->common->offset != 0))
		{
			bufc	= (bufc + t->common->offset);
			buf 	= bufc;
			buflen	-= t->common->offset;
		}
		//restrict depth if possible
		if ((buflen > t->common->depth) && (t->common->depth != 0))
			buflen = t->common->depth;
		
		nummatch = pcre_exec(t->common->regex_compiled, t->common->regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
		if (nummatch < 0) {
			#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
				if (nummatch == PCRE_ERROR_MATCHLIMIT) {
					if (option.debug == 21) 
					printf("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for file %s with the regex '%s'", t->common->servicename, t->common->matchstr);
				} //else
			#endif // PCRE_ERROR_MATCHLIMIT
		} else {
			if(option.debug == 21)
				printf("File match for session %lld : file %s\n",s->id, t->common->servicename);
					// Yeah!  Match apparently succeeded.
			file = (t_file *)malloc(sizeof(t_file));
			bzero(file, sizeof(t_file));

			// Now lets get captured variable
			if(t->name_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->name_template, file->name, sizeof(file->extension));
				if (rc != 0) 
					warning("Warning: File pattern matching failed to fill name_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->extension_template)? t->extension_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->extension_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->extension_template, file->extension, sizeof(file->extension));
				if (rc != 0) 
					warning("Warning: File pattern matching failed to fill extension_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->extension_template)? t->extension_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->familly_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->familly_template, file->familly, sizeof(file->familly));
				if (rc != 0) 
					warning("Warning: File pattern matching failed to fill familly_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->extension_template)? t->extension_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->headers_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->headers_template, file->headers, sizeof(file->headers));
				if (rc != 0) 
					warning("Warning: File pattern matching failed to fill headers_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->extension_template)? t->extension_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->additionnal_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->additionnal_template, file->additionnal, sizeof(file->additionnal));
				if (rc != 0) 
					warning("Warning: File pattern matching failed to fill additionnal_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->extension_template)? t->extension_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
					
			if(t->size != 0)
				file->size = t->size;
			if(t->entropy !=0)
				file->entropy = t->entropy;
			if(phase == DATA_PHASE)
				file->nature = DATA_PHASE;
			else
				file->nature = CONTROL_PHASE;
 			
			pthread_mutex_lock(&mutex.hashsession);
			if(s->last_file)
				s->last_file->next = file;

			else 
				s->file = file;
			s->last_file = file;
			pthread_mutex_unlock(&mutex.hashsession);
			
			//error analysis
			if (analyze.error && t->common->event_type == TYPE_ERROR)
				analyze_error(s, p, s->id, 0, p->ip->src,  TYPE_ERROR, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
			if (analyze.event && t->common->event_type == TYPE_EVENT)
				analyze_error(s, p, s->id, 0, p->ip->src, TYPE_EVENT, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
		
			//stating l4
			if(t->common->type)
				traffic_analyze_stat(s, p, stream, t->common->type); 
			//phase feedback
			if(t->common->next_phase)
				traffic_phase_feedback(s, p, t->common->next_phase);
			
			if(strncmp(t->common->servicename, "n/a",3) != 0)
				detection_protocol_pattern(s, p, t->common->servicename, t->common->confidence);
						
			if(need_to_return(t->common->policy))
				return;


		}		
		t = t->next;
	}
}

void traffic_pattern_match_packet_protocol(t_session *s, t_pkt *p)
{
	int 	buflen			= 0;
	int 	buflen_base		= 0; 		///!<used to keep buflen  befors rule alteration
	int 	rc, nummatch;
	int 	i 			= 0;
	char 	*bufc 			= p->payload;
	char	*buf 			= p->payload;
	int 	ovector[150]; 				///!<allows 50 substring matches (including the overall match)
	_u8 	phase 			= 0;
	_u8	stream 			= 0;
	t_traffic_protocol 	*t	= NULL;
	t_protocol_info		*proto 	= NULL;

	//add check here
	assert(s);
	assert(p);
	assert(s->proto > 0);
	assert(p->payload_len);
	
	//tuning inspection size 
	if (tuning.patternrestrictlen && p->payload_len > tuning.patternrestrictlen)
		buflen = tuning.patternrestrictlen;
	else
		buflen = p->payload_len;
	
	//saving original size
	buflen_base = buflen;
	
	
	//we are client style : ip src, port dst
	if(option.debug == 21)
		printf("doing protocol pattern matching on session %lld pkt %d for len %d\n", s->id, s->nb_pkt_in + s->nb_pkt_out, buflen);
	
	//use the phase detection luke
	if(p->ip->src == s->src)
	{
		stream = HOST_FROM;
		if (p->phase_client == CONTROL_PHASE)
		{
			t = protocol_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_client == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= dprotocol_patterns;
			phase = DATA_PHASE;
		}
	} else {
		stream = HOST_TO;
		if (p->phase_server == CONTROL_PHASE) {
			t = protocol_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_server == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= dprotocol_patterns;
			phase = DATA_PHASE;
		}
	}	
			
	while (t != NULL)
	{
		assert(t->common);
		assert(t->common->regex_compiled);
		i++;
		
		//restoring
		bufc 	= p->payload;
		buf 	= p->payload;
		buflen	= buflen_base;
		//pattern restriction according to rules options 
		//start offset
		if((t->common->offset <= buflen) && (t->common->offset != 0))
		{
			bufc	= (bufc + t->common->offset);
			buf 	= bufc;
			buflen	-= t->common->offset;
		}
		//restrict depth if possible
		if ((buflen > t->common->depth) && (t->common->depth != 0))
			buflen = t->common->depth;
		
		nummatch = pcre_exec(t->common->regex_compiled, t->common->regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
		if (nummatch < 0) {
			#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
			if (nummatch == PCRE_ERROR_MATCHLIMIT) {
				if (option.debug == 21) 
					warning("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", t->common->servicename, t->common->matchstr);
			} //else
			#endif // PCRE_ERROR_MATCHLIMIT
		} else {
			if(option.debug == 21)
				warning("Protocol match for session %lld : proto %s\n",s->id, t->common->servicename);
			// Yeah!  Match apparently succeeded.
			proto = (t_protocol_info *)malloc(sizeof(t_protocol_info));
			bzero(proto, sizeof(t_protocol_info));
			strncpy(proto->name, t->common->servicename, sizeof(proto->name)); 

			// Now lets get captured variable
			if(t->familly_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->familly_template, proto->familly, sizeof(proto->familly));
				if (rc != 0) 
					warning("Warning: Protocol pattern matching failed to fill familly_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->version_template)? t->version_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->version_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->version_template, proto->version, sizeof(proto->version));
				if (rc != 0) 
					warning("Warning: Protocol pattern matching failed to fill version_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->version_template)? t->version_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->additionnal_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->additionnal_template, proto->additionnal, sizeof(proto->additionnal));
				if (rc != 0) 
					warning("Warning: Protocol pattern matching failed to fill additionnal_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->version_template)? t->version_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			if(t->encrypted_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->encrypted_template, proto->encrypted, sizeof(proto->encrypted));
				if (rc != 0) 
					warning("Warning: Protocol pattern matching failed to fill encrypted_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->familly_template)? t->familly_template : "", (t->version_template)? t->version_template : "", (t->additionnal_template)? t->additionnal_template : "");
			}
			
			if(proto->encrypted == '\0')
				strcpy(proto->encrypted, "plain text");
			if(phase == DATA_PHASE)
			proto->nature = DATA_PHASE;
			else
			proto->nature = CONTROL_PHASE;
			
			
			//tail add
			pthread_mutex_lock(&mutex.hashsession);
				if(s->last_protocol)
					s->last_protocol->next = proto;
				else 
					s->protocol = proto;
				s->last_protocol = proto;
			pthread_mutex_unlock(&mutex.hashsession);
			
			if (analyze.error && t->common->event_type == TYPE_ERROR)
				analyze_error(s, p, s->id, 0, p->ip->src,  TYPE_ERROR, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
			if (analyze.event && t->common->event_type == TYPE_EVENT)
				analyze_error(s, p, s->id, 0, p->ip->src, TYPE_EVENT, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
	
				
			//stating l4
			if(t->common->type)
				traffic_analyze_stat(s, p, stream, t->common->type); 
			//phase feedback
			if(t->common->next_phase)
				traffic_phase_feedback(s, p, t->common->next_phase);
			
			//Dynamic content protocol detection signature feedback 
			if(strncmp(t->common->servicename, "n/a",3) != 0)
				detection_protocol_pattern(s, p, t->common->servicename, t->common->confidence);

			if(need_to_return(t->common->policy))
				return;
		}
		t= t->next;
	}
}
void traffic_pattern_match_packet_software(t_session *s, t_pkt *p, _u8 type)
{
	int			buflen 		= 0;
	int 			buflen_base	= 0; 		///!<used to keep buflen  befors rule alteration
	int 			rc, nummatch;
	int 			i 		= 0;
	char 	 		*bufc		= p->payload;
	char			*buf 		= p->payload;
	t_traffic_software 	*t 		= NULL;
	t_software		*soft		= NULL;
	int 			ovector[150]; ///!<allows 50 substring matches (including the overall match)
	_u8 			phase 		= 0;
	_u8			stream 		= 0;
	
	//add check here
	assert(s);
	assert(p);
	assert(s->proto > 0);
	assert(p->payload_len);
	//tuning inspection size 
	if (tuning.patternrestrictlen && p->payload_len > tuning.patternrestrictlen)
		buflen = tuning.patternrestrictlen;
	else
		buflen = p->payload_len;
	
	
	//saving original size
	buflen_base = buflen;
	
	
	//we are client style : ip src, port dst
	if(option.debug == 22)
		printf("doing Software pattern matching on session %lld pkt %d for len %d\n", s->id, s->nb_pkt_in + s->nb_pkt_out, buflen);
	
	//use the phase detection luke
	if(p->ip->src == s->src)
	{
		stream = HOST_FROM;
		if(tuning.usedirectionnal != 0 && s->state != SESS_PARTIAL_TCP)
			assert(type == SOFT_CLIENT);
		if (p->phase_client == CONTROL_PHASE)
		{
			t = (type == SOFT_CLIENT) ? client_patterns : server_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_client == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= (type == SOFT_CLIENT) ? dclient_patterns : dserver_patterns;;
			phase = DATA_PHASE;
		}
	} else {
		stream = HOST_TO;
		if (p->phase_server == CONTROL_PHASE) {
			t = (type == SOFT_CLIENT) ? client_patterns : server_patterns;;
			phase = CONTROL_PHASE;
		} else if (p->phase_server == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= (type == SOFT_CLIENT) ? dclient_patterns : dserver_patterns;;
			phase = DATA_PHASE;
		}
	}
	
				
	while (t != NULL)
	{
		assert(t->common);
		assert(t->common->regex_compiled);
		i++;
		
		
		//restoring
		bufc 	= p->payload;
		buf 	= p->payload;
		buflen	= buflen_base;
		//pattern restriction according to rules options 
		//start offset
		if((t->common->offset <= buflen) && (t->common->offset != 0))
		{
			bufc	= (bufc + t->common->offset);
			buf 	= bufc;
			buflen	-= t->common->offset;
		}
		//restrict depth if possible
		if ((buflen > t->common->depth) && (t->common->depth != 0))
			buflen = t->common->depth;
		
		
		
		nummatch = pcre_exec(t->common->regex_compiled, t->common->regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
		if (nummatch < 0) {
			#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
			if (nummatch == PCRE_ERROR_MATCHLIMIT) {
				if (option.debug == 22) 
					printf("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", t->common->servicename, t->common->matchstr);
			} //else
			#endif // PCRE_ERROR_MATCHLIMIT
		} else {
			if(option.debug == 22)
				printf("Software match for session %lld : proto %s\n",s->id, t->common->servicename);
			// Yeah!  Match apparently succeeded.
			soft = (t_software *)malloc(sizeof(t_software));
			bzero(soft, sizeof(t_software));
			strncpy(soft->protocol, t->common->servicename, sizeof(soft->protocol)); 
			soft->proto = s->proto;			

			// Now lets get captured variable
			if(t->product_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->product_template, soft->product, sizeof(soft->product));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill product_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}


			if(t->version_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->version_template, soft->version, sizeof(soft->version));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill version_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}

			if(t->familly_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->familly_template, soft->familly, sizeof(soft->familly));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill familly_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}

			if(t->info_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->info_template, soft->info, sizeof(soft->info));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill info_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}

			if(t->hostname_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->hostname_template, soft->hostname, sizeof(soft->hostname));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill hostname_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}

			if(t->ostype_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->ostype_template, soft->ostype, sizeof(soft->ostype));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill os_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}

			if(t->devicetype_template != NULL) {
				rc = dotmplsubst(buf, buflen, ovector, nummatch, t->devicetype_template, soft->devicetype, sizeof(soft->devicetype));
				if (rc != 0) 
					warning("Warning: Software pattern matching failed to fill devicetype_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/%s", buf,  (t->product_template)? t->product_template : "", (t->version_template)? t->version_template : "", (t->info_template)? t->info_template : "");
			}
			
			
			if(phase == DATA_PHASE)
				soft->nature = DATA_PHASE;
			else
				soft->nature = CONTROL_PHASE;
			
			soft->type = type;

			if(type == SOFT_CLIENT)
			{
				soft->ip = s->src;
				soft->port = s->sport;
			} else {
				soft->ip = s->dst;
				soft->port = s->dport;
			}
			
			//adding to software hash if needed and adding it to the list if not present
			if(analyze_software(soft))
			{
				pthread_mutex_lock(&mutex.hashsession);
				//client or server
				if(type == SOFT_CLIENT)
				{
					if(s->last_client)
						s->last_client->next = soft;
					else 
						s->client = soft;
					s->last_client = soft;
				} else {
					if(s->last_server)
						s->last_server->next = soft;
					else 
						s->server = soft;
					s->last_server = soft;
				}
				pthread_mutex_unlock(&mutex.hashsession);
			}
			
			if (analyze.error && t->common->event_type == TYPE_ERROR)
				analyze_error(s, p, s->id, 0, p->ip->src,  TYPE_ERROR, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
			if (analyze.event && t->common->event_type == TYPE_EVENT)
				analyze_error(s, p, s->id, 0, p->ip->src, TYPE_EVENT, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
				
			//stating l4
			if(t->common->type)
				traffic_analyze_stat(s, p, stream, t->common->type); 
			//phase feedback
			if(t->common->next_phase)
				traffic_phase_feedback(s, p, t->common->next_phase);
			
			//Dynamic content protocol detection signature feedback 
			if(strncmp(t->common->servicename, "n/a",3) != 0)
				detection_protocol_pattern(s, p, t->common->servicename, t->common->confidence);
			
			if(need_to_return(t->common->policy))
				return;
		}
		t= t->next;
	}
}

void traffic_pattern_match_packet_user(t_session *s, t_pkt *p)
{
	int buflen = 0;
	int 	buflen_base		= 0; 		///!<used to keep buflen  befors rule alteration
	int rc, nummatch;
	int i = 0;
	char 	 		*bufc = p->payload;
	char			*buf = p->payload;
	t_traffic_user 		*t = NULL;
	t_user			*user = NULL;
	int 			ovector[150]; ///!<allows 50 substring matches (including the overall match)
	_u8 			phase = 0;
	_u8			stream = 0;
	
	//add check here
	assert(s);
	assert(p);
	assert(s->proto > 0);
	assert(p->payload_len);
	
	//tuning inspection size 
	if (tuning.patternrestrictlen && p->payload_len > tuning.patternrestrictlen)
		buflen = tuning.patternrestrictlen;
	else
		buflen = p->payload_len;
	
	
	
	//saving original size
	buflen_base = buflen;
	
	
	//we are client style : ip src, port dst
	if(option.debug == 24)
		printf("doing user pattern matching on session %lld pkt %d for len %d\n", s->id, s->nb_pkt_in + s->nb_pkt_out, buflen);
	
	//use the phase detection luke
	if(p->ip->src == s->src)
	{
		stream = HOST_FROM;
		if (p->phase_client == CONTROL_PHASE)
		{
			t = user_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_client == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= duser_patterns;
			phase = DATA_PHASE;
		}
	} else {
		stream = HOST_TO;
		if (p->phase_server == CONTROL_PHASE) {
			t = user_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_server == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= duser_patterns;
			phase = DATA_PHASE;
		}
	}
	
				
	while (t != NULL)
	{
		assert(t->common);
		assert(t->common->regex_compiled);
		i++;
		
		
		//restoring
		bufc 	= p->payload;
		buf 	= p->payload;
		buflen	= buflen_base;
		//pattern restriction according to rules options 
		//start offset
		if((t->common->offset <= buflen) && (t->common->offset != 0))
		{
			bufc	= (bufc + t->common->offset);
			buf 	= bufc;
			buflen	-= t->common->offset;
		}
		//restrict depth if possible
		if ((buflen > t->common->depth) && (t->common->depth != 0))
			buflen = t->common->depth;
		
		
		nummatch = pcre_exec(t->common->regex_compiled, t->common->regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
		if (nummatch < 0) {
#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
			if (nummatch == PCRE_ERROR_MATCHLIMIT) {
	if (option.debug == 24) 
		printf("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", t->common->servicename, t->common->matchstr);
			} //else
#endif // PCRE_ERROR_MATCHLIMIT
		} else {
	if(option.debug == 24)
		printf("User match for session %lld : proto %s\n",s->id, t->common->servicename);
			// Yeah!  Match apparently succeeded.
	user = (t_user *)malloc(sizeof(t_user));
	bzero(user, sizeof(t_user));
	strncpy(user->protocol, t->common->servicename, sizeof(user->protocol)); 
	if(p->ip)
		user->ip = p->ip->src;
	
	// Now lets get captured variable
	if(t->familly_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->familly_template, user->familly, sizeof(user->familly));
		if (rc != 0) 
			warning("Warning: User pattern matching failed to fill familly_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	if(t->login_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->login_template, user->login, sizeof(user->login));
		if (rc != 0)
			warning("Warning: User pattern matching failed to fill login_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	if(t->additionnal_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->additionnal_template, user->additionnal, sizeof(user->additionnal));
		if (rc != 0) 
			warning("Warning: User pattern matching failed to fill additionnal_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	if(t->pass_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->pass_template, user->pass, sizeof(user->pass));
		if (rc != 0) 
			warning("Warning: User pattern matching failed to fill additionnal_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	if(t->algorithm_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->algorithm_template, user->algorithm, sizeof(user->algorithm));
		if (rc != 0) 
			warning("Warning: User pattern matching failed to fill algorithm_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	if(t->origin_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->origin_template, user->origin, sizeof(user->origin));
		if (rc != 0) 
			warning("Warning: User pattern matching failed to fill origin_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->login_template)? t->login_template : "");
	}
	//nature of the file
	user->nature = t->nature;

	//adding it to user hashtable if needed
	if (analyze_user(user))
	{
		
		//adding it to session if needed
		pthread_mutex_lock(&mutex.hashsession);
		if(s->last_user)
			s->last_user->next = user;
		else 
			s->user = user;
		s->last_user = user;
		pthread_mutex_unlock(&mutex.hashsession);
	}
	if (analyze.error && t->common->event_type == TYPE_ERROR)
		analyze_error(s, p, s->id, 0, p->ip->src,  TYPE_ERROR, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
	if (analyze.event && t->common->event_type == TYPE_EVENT)
		analyze_error(s, p, s->id, 0, p->ip->src, TYPE_EVENT, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
	
	//stating l4
	if(t->common->type)
		traffic_analyze_stat(s, p, stream, t->common->type); 
	//phase feedback
	if(t->common->next_phase)
		traffic_phase_feedback(s, p, t->common->next_phase);
	
				//Dynamic content protocol detection signature feedback 
			if(strncmp(t->common->servicename, "n/a",3) != 0)
				detection_protocol_pattern(s, p, t->common->servicename, t->common->confidence);
	if(need_to_return(t->common->policy))
		return;
	}
	t = t->next;
	}
}

void traffic_pattern_match_packet_user2user(t_session *s, t_pkt *p)
{
	int 	buflen = 0;
	int 	buflen_base		= 0; 		///!<used to keep buflen  befors rule alteration
	int rc, nummatch;
	int i = 0;
	char 	 		*bufc = p->payload;
	char			*buf = p->payload;
	t_traffic_user_to_user 	*t = NULL;
	t_user_to_user		*u2u = NULL;
	int 			ovector[150]; ///!<allows 50 substring matches (including the overall match)
	_u8 			phase = 0;
	_u8			stream = 0; ///!< either client or server
	//add check here
	assert(s);
	assert(p);
	assert(s->proto > 0);
	assert(p->payload_len);
	
	//tuning inspection size 
	if (tuning.patternrestrictlen && p->payload_len > tuning.patternrestrictlen)
		buflen = tuning.patternrestrictlen;
	else
		buflen = p->payload_len;
	
	
	//saving original size
	buflen_base = buflen;
	
	
	//we are client style : ip src, port dst
	if(option.debug == 25)
		printf("doing User 2 User pattern matching on session %lld pkt %d for len %d\n", s->id, s->nb_pkt_in + s->nb_pkt_out, buflen);
	
	//use the phase detection luke
	if(p->ip->src == s->src)
	{
		stream = HOST_FROM;
		if (p->phase_client == CONTROL_PHASE)
		{
			t = user_to_user_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_client == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= duser_to_user_patterns;
			phase = DATA_PHASE;
		}
	} else {
		stream = HOST_TO;
		if (p->phase_server == CONTROL_PHASE) {
			t = user_to_user_patterns;
			phase = CONTROL_PHASE;
		} else if (p->phase_server == DATA_PHASE && (s->file_client_last_pkt_num < tuning.contentpktnum || tuning.contentpktnum == 0)) {
			t= duser_to_user_patterns;
			phase = DATA_PHASE;
		}
	}
	
				
	while (t != NULL)
	{
		assert(t->common);
		assert(t->common->regex_compiled);
		i++;
		
		
		//restoring
		bufc 	= p->payload;
		buf 	= p->payload;
		buflen	= buflen_base;
		//pattern restriction according to rules options 
		//start offset
		if((t->common->offset <= buflen) && (t->common->offset != 0))
		{
			bufc	= (bufc + t->common->offset);
			buf 	= bufc;
			buflen	-= t->common->offset;
		}
		//restrict depth if possible
		if ((buflen > t->common->depth) && (t->common->depth != 0))
			buflen = t->common->depth;
		
		
		nummatch = pcre_exec(t->common->regex_compiled, t->common->regex_extra, bufc, buflen, 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
		if (nummatch < 0) {
#ifdef PCRE_ERROR_MATCHLIMIT  // earlier PCRE versions lack this
			if (nummatch == PCRE_ERROR_MATCHLIMIT) {
				if (option.debug == 25) 
					printf("Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service %s with the regex '%s'", t->common->servicename, t->common->matchstr);
			} //else
#endif // PCRE_ERROR_MATCHLIMIT
			;
	} else {
	if(option.debug == 25)
		printf("User to user match for session %lld : proto %s\n",s->id, t->common->servicename);
	u2u = (t_user_to_user *)malloc(sizeof(t_user_to_user));
	bzero(u2u, sizeof(t_user_to_user));
	strncpy(u2u->protocol, t->common->servicename, sizeof(u2u->protocol)); 
	if(p->ip)
		u2u->ip = p->ip->src;
	

	// Now lets get captured variable
	if(t->familly_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->familly_template, u2u->familly, sizeof(u2u->familly));
		if (rc != 0) 
			warning("Warning: User2User pattern matching failed to fill familly_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->sender_template)? t->sender_template : "");
	}
	if(t->sender_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->sender_template, u2u->sender, sizeof(u2u->sender));
		if (rc != 0)
			warning("Warning: User2User pattern matching failed to fill sender_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->sender_template)? t->sender_template : "");
	}
	if(t->receiver_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->receiver_template, u2u->receiver, sizeof(u2u->receiver));
		if (rc != 0)
			warning("Warning: User2User pattern matching failed to fill receiver_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->sender_template)? t->sender_template : "");
	}
	if(t->additionnal_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->additionnal_template, u2u->additionnal, sizeof(u2u->additionnal));
		if (rc != 0) 
			warning("Warning: User2User pattern matching failed to fill additionnal_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->sender_template)? t->sender_template : "");
	}
	if(t->origin_template != NULL) {
		rc = dotmplsubst(buf, buflen, ovector, nummatch, t->origin_template, u2u->origin, sizeof(u2u->origin));
		if (rc != 0) 
			warning("Warning: User2User pattern matching failed to fill origin_template (subjectlen: %d). Too long? Match string was line: v/%s/%s/", buf,  (t->familly_template)? t->familly_template : "", (t->sender_template)? t->sender_template : "");
	}
	///! nature of the file
	u2u->nature = t->nature;

	
	//adding it to user hashtable if needed
	if(analyze_user2user(u2u))
	{
		//adding it to session
		pthread_mutex_unlock(&mutex.hashsession);
		if(s->last_user2user)
			s->last_user2user->next = u2u;
		else 
			s->user2user = u2u;
		s->last_user2user = u2u;
		pthread_mutex_unlock(&mutex.hashsession);
	}
	
	//error report
	if (analyze.error && t->common->event_type == TYPE_ERROR)
		analyze_error(s, p, s->id, 0, p->ip->src,  TYPE_ERROR, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
	if (analyze.event && t->common->event_type == TYPE_EVENT)
		analyze_error(s, p, s->id, 0, p->ip->src, TYPE_EVENT, '4', t->common->class_shortname, t->common->event_name, t->common->event_nature, t->common->event_details, t->common->event_target, s->last_time, s->last_time_usec);
	
	//stating l4
	if(t->common->type)
		traffic_analyze_stat(s, p, stream, t->common->type); 
	//phase feedback
	if(t->common->next_phase)
		traffic_phase_feedback(s, p, t->common->next_phase);
	
				//Dynamic content protocol detection signature feedback 
			if(strncmp(t->common->servicename, "n/a",3) != 0)
				detection_protocol_pattern(s, p, t->common->servicename, t->common->confidence);
	if(need_to_return(t->common->policy))
		return;
		}
		t= t->next;
	}
}
