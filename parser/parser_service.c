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
 *       \file parser_service.c
 *       \brief Used to parse standard service file in block <Services>
 *
 *       Use a pseudo xml as apache do.
 *       \author  Elie
 *       \version 1.0
 *       \date    July 2006
 */


extern	t_option	option;
extern	t_tab_services	services;

/*!
 * Parsing Services block 
 * @param fp  the file pointer to parse
 * @param l the line in the conf
 * @see parse_conf()
 * @return when block is over
 * \version 1.0
 * \date    2006
 * \author Elie
 */
 
int parse_services_block(FILE *fp, int l)
{
	char 			line[1024];
	ssize_t     		r;
	_u32			res;
	char 			servicename[128], proto[16];
	_u16 			portno;
	_u16 numtcpports= 0, numudpports = 0;
	/* Parsing the configuration files and the if the syntax is correct */
	bzero(line, sizeof(line));
	while ((fgets(line, sizeof(line), fp)))
	{
		l++;
		if (!(r = strncmp(line,"</Services>",10)))
		{
			if (option.debug == 42)
				printf("Services block parsing finish : %d tcp and %d udp services found\n",numtcpports, numudpports );
			return 1;
		}
		//comment
		if (parse_is_comment(line))
			continue; 
		res = sscanf(line, "%127s %hu/%15s", servicename, &portno, proto);
		if (res !=3)
			die("Service syntax error at line %d unreconized port number %s\n", l, line);
		portno = htons(portno);
		if (strncasecmp(proto, "tcp", 3) == 0) {
			numtcpports++;
			services.tcp[portno].name = (char *)my_strndup(servicename, strlen(servicename));
		} else if (strncasecmp(proto, "udp", 3) == 0) {
			numudpports++;
			services.udp[portno].name = (char *)my_strndup(servicename, strlen(servicename));
		} else if (strncasecmp(proto, "ddp", 3) == 0) {
			/* ddp is some apple thing...we don't "do" that */
		} else if (strncasecmp(proto, "divert", 6) == 0) {
			/* divert sockets are for freebsd's natd */
		} else if (strncasecmp(proto, "icmp", 4) == 0) {
			warning("Service : %s  line : %d Nice try ! but icmp does not have port, need to go back in school ;)",proto,l);
		} else {
			if (option.debug == 42)
				warning("Service Unknown protocol (%s) on line %d.\n", proto, l);
			continue;
		}
		bzero(line, sizeof(line));
	}
  return 1;
}
