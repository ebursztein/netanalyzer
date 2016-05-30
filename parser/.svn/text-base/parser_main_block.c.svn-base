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
 *       \file parser_main_block.c
 *       \brief Used to parse main instruction block <Netprof>
 *
 *       Use a pseudo xml as apache do.
 *       \author  Elie
 *       \version 1.0
 *       \date    July 2006
 */


extern	t_option	option;
extern	t_analyze	analyze;


/*!
 * Parsing main option block 
 * @param fp  the file pointer to parse
 * @param l the line in the conf
 * @see parse_conf()
 * @return when block is over
 * \version 1.0
 * \date    2006
 * \author Elie
 */
 
int parse_main_block(FILE *fp, int l)
{
	char 			line[1024], *optvalue=  NULL;
	_u32			count = 0;

	/* Parsing the configuration files and the if the syntax is correct */
	while ((fgets(line, sizeof(line), fp)))
	{
		l++;
		if (!(strncmp(line,"</General>",10)))
		{
			if (option.debug == 42)
				printf("Main block parsing finish : %d instructions found\n", count);
			return 1;
		}
		//comment
		if (parse_is_comment(line))
			continue; 
		optvalue=line;
	
		if(strncmp(line, "snaplen", 7) == 0) {
			optvalue = optvalue + 7;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			option.snaplen = atoi(optvalue);
			count++;
			
					
			//LIMIT THE OUTPUT
			
		} else if(strncmp(line, "sessionlimit", 12) == 0) {
			optvalue = optvalue + 12;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.session = atoi(optvalue);
			count++;
		} else if(strncmp(line, "hostlimit", 9) == 0) {
			optvalue = optvalue + 9;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.host = atoi(optvalue);
			count++;
		} else if(strncmp(line, "protocollimit", 13) == 0) {
			optvalue = optvalue + 13;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.protocol = atoi(optvalue);
			count++;
		} else if(strncmp(line, "errorlimit", 10) == 0) {
			optvalue = optvalue + 10;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.sanity = atoi(optvalue);
			count++;
		} else if(strncmp(line, "softwarelimit", 13) == 0) {
			optvalue = optvalue + 13;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.software = atoi(optvalue);
			count++;
		} else if(strncmp(line, "userlimit", 9) == 0) {
			optvalue = optvalue + 9;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.user = atoi(optvalue);
			count++;
				
			
		//ANALYZE ACTIVATION
			
		} else if(strncmp(line, "session", 7) == 0) {
			optvalue = optvalue + 7;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.session = -1;
			count++;
		} else if(strncmp(line, "host", 4) == 0) {
			optvalue = optvalue + 4;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.host = -1;
			count++;
		} else if(strncmp(line, "protocol", 8) == 0) {
			optvalue = optvalue + 8;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.protocol = -1;
			count++;
		} else if(strncmp(line, "error", 5) == 0) {
			optvalue = optvalue + 5;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.sanity = -1;
			count++;
		} else if(strncmp(line, "software", 8) == 0) {
			optvalue = optvalue + 8;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.software = -1;
			count++;
		} else if(strncmp(line, "user", 4) == 0) {
			optvalue = optvalue + 4;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.user = -1;
			count++;
		} else if(strncmp(line, "tcpdump", 7) == 0) {
			optvalue = optvalue + 7;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.tcpdump = -1;
			count++;
		} else if(strncmp(line, "network", 7) == 0) {
			optvalue = optvalue + 7;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.network = -1;
			count++;	
		} else if(strncmp(line, "advanced", 8) == 0) {
			optvalue = optvalue + 8;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			analyze.advanced = -1;
			count++;
			

			
		} else if(strncmp(line, "intervall", 9) == 0) {
			optvalue = optvalue + 9;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			option.intervall = atoi(optvalue);
			count++;
		} else if(strncmp(line, "fancy", 5) == 0) {
			optvalue = optvalue + 5;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			option.fancy = atoi(optvalue);
			count++;
		} else if(strncmp(line, "xml", 3) == 0) {
			optvalue = optvalue + 3;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			option.xml = atoi(optvalue);
			count++;
		} else if(strncmp(line, "debuglevel", 10) == 0) {
			optvalue = optvalue + 10;
			if (parse_is_option_affect_op(optvalue))
				optvalue++;
			else
				die("Netprof block parsing syntax error at line %d unreconized affect caracter %c\n", l, optvalue[0]);
			option.debug = atoi(optvalue);
			count++;
		} else {
			die("General block parsing syntax error at line %d unreconized option %s\n", l, line);
		}
		bzero(line,sizeof(line));
	}
  return 1;
}
