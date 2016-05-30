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
#include <assert.h>
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"

/*!
 *       \file parser_macprefix.c
 *       \brief Used to parse mac address prefix
 *
 *       Use a pseudo xml as apache do.
 *       \author  Elie
 *       \version 1.0
 *       \date    July 2006
 */


extern	t_option	option;
extern	t_hash		*macaddrs;

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
 
int parse_macprefix_block(FILE *fp, int l)
{
	char 			line[1024];
	_u32			count = 0;
	int pfx;
	char *endptr, *p;
	/* Parsing the configuration files and the if the syntax is correct */
	while ((fgets(line, sizeof(line), fp)))
	{
		l++;
		if (!(strncmp(line,"</Macprefix>",12)))
		{
			if (option.debug == 42)
				printf("Mac prefix parsing finish : %d prefix found\n", count);
			return 1;
		}
		//comment
		if (parse_is_comment(line))
			continue; 
		if (!isxdigit(*line)) 
			die("Mac prefix Parse error one line %d of %s.\n", l);
		/* First grab the prefix */
		pfx = strtol(line, &endptr, 16);
		if (!endptr || !isspace(*endptr)) 
			die("Mac prefix Parse error one line %d.\n", l);
		/* Now grab the vendor */
		while(*endptr && isspace(*endptr)) endptr++;
		assert(*endptr);
		p = endptr;
		while(*endptr && *endptr != '\n' && *endptr != '\r') endptr++;
		*endptr = '\0';
		macprefix_add(pfx, p);
		count++;
		bzero(line,sizeof(line));
	}
  return 1;
}
