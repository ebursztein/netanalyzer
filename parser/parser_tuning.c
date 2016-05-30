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

/*!
 *       \file parser_tuning.c
 *       \brief Used to parse tuning analysis options <Tuning>
 *
 *       Use a pseudo xml as apache do.
 *       \author  Elie
 *       \version 1.0
 *       \date    July 2006
 */


extern	t_option	option;
extern	t_tuning	tuning;
extern	char		parser_current_file[];


/*!
 * Parsing tumimg option block 
 * @param fp  the file pointer to parse
 * @param l the line in the conf
 * @see parse_conf()
 * @return when block is over
 * \version 1.0
 * \date    2006
 * \author Elie
 */
 
int parse_tuning_block(FILE *fp, int l)
{
	char 			line[1024], *optvalue=  NULL;
	_u32			count = 0;

	/* Parsing the configuration files and the if the syntax is correct */
	while ((fgets(line, sizeof(line), fp)))
	{
		l++;
		if (!(strncmp(line,"</Tuning>",9)))
		{
			if (option.debug == 42)
				printf("Tuning block parsing finish : %d instructions found\n", count);
			return 1;
		}
		//comment
		if (parse_is_comment(line))
			continue; 
		optvalue=line;
	
		if(strncmp(line, "profile_restrict_len", 20) == 0) {
			optvalue = optvalue + 20;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.profile_restrict_len = atoi(optvalue);
			if (!tuning.profile_restrict_len)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useprofile", 10) == 0) {
			optvalue = optvalue + 10;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useprofile = atoi(optvalue);
			if (!tuning.useprofile)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "usepattern", 10) == 0) {
			optvalue = optvalue + 10;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.usepattern = atoi(optvalue);
			if (!tuning.usepattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "usetrafficpattern", 17) == 0) {
			optvalue = optvalue + 17;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.usetrafficpattern = atoi(optvalue);
			if (!tuning.usetrafficpattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useserverpattern", 16) == 0) {
			optvalue = optvalue + 16;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useserverpattern = atoi(optvalue);
			if (!tuning.useserverpattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useclientpattern", 16) == 0) {
			optvalue = optvalue + 16;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useclientpattern = atoi(optvalue);
			if (!tuning.useclientpattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "usefilepattern", 14) == 0) {
			optvalue = optvalue + 14;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.usefilepattern = atoi(optvalue);
			if (!tuning.usefilepattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useuserpattern", 14) == 0) {
			optvalue = optvalue + 14;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useuserpattern = atoi(optvalue);
			if (!tuning.useuserpattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useu2upattern", 13) == 0) {
			optvalue = optvalue + 13;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useu2upattern = atoi(optvalue);
			if (!tuning.useu2upattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useerrorpattern", 15) == 0) {
			optvalue = optvalue + 15;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useerrorpattern = atoi(optvalue);
			if (!tuning.useerrorpattern)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "useadvancedtracking", 19) == 0) {
			optvalue = optvalue + 19;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.useadvancedtracking = atoi(optvalue);
			if (!tuning.useadvancedtracking)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "usechkcover", 11) == 0) {
			optvalue = optvalue + 11;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.usechkcover = atoi(optvalue);
			if (!tuning.usechkcover)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "usedirectionnal", 15) == 0) {
			optvalue = optvalue + 15;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.usedirectionnal = atoi(optvalue);
			if (!tuning.usedirectionnal)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "patternsignaturemultimatch", 26) == 0) {
			optvalue = optvalue + 26;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.patternsignaturemultimatch = atoi(optvalue);
			if (!tuning.patternsignaturemultimatch)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "nbpktinit", 9) == 0) {
			optvalue = optvalue + 9;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.nbpktinit = atoi(optvalue);
			if (!tuning.nbpktinit)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "nbpktcontent", 12) == 0) {
			optvalue = optvalue + 12;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.contentpktnum = atoi(optvalue);
			if (!tuning.contentpktnum)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "pattern_restrict_len", 20) == 0) {
			optvalue = optvalue + 20;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.patternrestrictlen = atoi(optvalue);
			if (!tuning.patternrestrictlen)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		} else if(strncmp(line, "dump_profile", 12) == 0) {
			optvalue = optvalue + 12;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
			tuning.dump_profile = atoi(optvalue);
			if (!tuning.dump_profile)
				die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
			count++;
		}  else if(strncmp(line, "port_confidence", 15) == 0) {
				optvalue = optvalue + 15;
				if (parse_is_option_affect_op(optvalue))
					optvalue++;
				else
					die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
				tuning.port_heuristic_confidence = atoi(optvalue);
				if (!tuning.port_heuristic_confidence)
					die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
				if (tuning.port_heuristic_confidence > 100)
					die("Port heuristic percentage confidence can't be higher than 100\%\n");
				count++;
		}  else if(strncmp(line, "weight_port", 11) == 0) {
				optvalue = optvalue + 11;
				if (parse_is_option_affect_op(optvalue))
					optvalue++;
				else
					die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
				tuning.weight_port = atoi(optvalue);
				if (!tuning.weight_port)
					die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
				count++;
		}  else if(strncmp(line, "weight_pattern", 14) == 0) {
				optvalue = optvalue + 14;
				if (parse_is_option_affect_op(optvalue))
					optvalue++;
				else
					die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
				tuning.weight_pattern = atoi(optvalue);
				if (!tuning.weight_pattern)
					die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
				count++;
		}  else if(strncmp(line, "weight_profile", 14) == 0) {
				optvalue = optvalue + 14;
				if (parse_is_option_affect_op(optvalue))
					optvalue++;
				else
					die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
				tuning.weight_profile = atoi(optvalue);
				if (!tuning.weight_profile)
					die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
				count++;
		
		}  else if(strncmp(line, "proba_display", 13) == 0) {
				optvalue = optvalue + 13;
				if (parse_is_option_affect_op(optvalue))
					optvalue++;
				else
					die("%s:%d:\tParsing syntax error recognized affectation caractere: '%c'\n",parser_current_file, l, optvalue[0]);
				tuning.proba_display = atoi(optvalue);
				//if (!tuning.proba_display) <- can be 0
				//	die("%s:%d:\tTuning block: option syntax error: option is equal to 0 (and therefore shoud  be commented out) or have and should be written  \"option=value\" instead of  \"option = value\"\n",parser_current_file, l);
				if (tuning.proba_display > 100)
					die("%s:%d:\tTuning block: proba_display: value need to be between 0 and 100\n",parser_current_file, l);
				count++;
		} else 
			die("%s:%d:\tTuning option unknown: %s",parser_current_file, l, line);
		bzero(line,sizeof(line));
	}	
  return 1;
}
