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
 * \file common_function.c
 * \brief commom function used for output
 * \author  Elie
 * \version 1.0
 * \date    Feb 2007
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include "../headers/structure.h"

extern	t_option 	option;
extern	fd_set 		active_fd_set;

//traf units
static char *traf_unit[] = {
	"b",
	"Kb",
	"Mb",
	"Gb",
};


/*!
 * exit facility 
 * @param error message
 * \version 1.0
 * \date    2006
 * \author Elie
 */
void die(char *err, ...) 
{
	va_list ap;
	va_start(ap, err);
	fflush(stdout);
	vfprintf(stderr, err, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

/*!
 * Warning facility 
 * @param error message
 * \version 1.0
 * \date    Feb 2007
 * \author Elie
 */
void warning(char *err, ...) 
{
	//no warning if in quiet mode
	if(option.quiet)
		return;
	va_list ap;
	va_start(ap, err);
	if(option.errout)
		vfprintf(option.errout, err, ap);
	else
		vfprintf(stderr, err, ap);
	va_end(ap);
	//exit(EXIT_FAILURE);
}


/*!
 * unified output function 
 * @param str the string to output
 * \version 1.1
 * \date   Feb 2007
 * \author Elie
 */
int out(char *str, ...) 
{
	//dowing a buffer might be nice
	int res;
	va_list ap;

	/*if(option.deamon > 0)
	{
		for(res  = FD_SETSIZE; res; res--)
			if (FD_ISSET(res, &active_fd_set))
				send(res, str, strlen(str), 0);
	} */
	
	va_start(ap, str);
	res = vfprintf(option.fileout, str, ap);
	va_end(ap);
	return res;
}


//painfull situation > if online then we need packet by second according to the 
// time of catpture
//on the other hand if offline we need the nb packet by second according to the time in the dump
//cheers
//we also need conversion to mb/s etc so the most clean way is wrapper with no malloc for performance reasons.


//generic output function for trafic

void output_trafic(int value, char *buf)
{
	int type=0;
	
	//no malloc
	bzero(buf, BUFF_S);

	if(value)
	{
		//printf("val:%d type:", value);
		if(value - 1073741824 > 1) {
			type = 3;
			value /= 1073741824;
		} else if (value - 1048576 > 1) {
			type = 2;
			value /= 1048576;
		} else  if (value - 1024 > 1) {
			type = 1;
			value /= 1024;
		} else {
			//printf("0 unit:%s\n",traf_unit[type]);
			;
		}
		snprintf(buf, BUFF_S,"%d %s", value, traf_unit[type]);
	} else {
		snprintf(buf, BUFF_S,"0 o");
	}

}

void output_trafic_by_sec(int value, char *buf)
{
	return output_trafic(value/ option.intervall, buf);
}

//used to divid any value to put it by sec
int output_value_by_sec(int value)
{
	//no malloc
	return (value / option.intervall);
}
