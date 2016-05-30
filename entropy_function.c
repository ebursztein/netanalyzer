/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/**
 ** \file file-ent.c
 ** 
 ** Minor revision to integrate to netAnalyzer but code remain mostly unchanged
 ** 
 ** \author Julien OLIVAIN <julien.olivain@lsv.ens-cachan.fr>
 ** 
 ** \version 0.1.0
 ** 
 ** \date  Started on: Mon Dec 20 11:32:33 2004
 ** \date Last update: Fri Jul 29 12:51:25 2005
 **/
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"
#include "headers/protocol.h"


entropy_t compute_mm_entropy(entropy_t e, unsigned long *dist, size_t msglen)
{
	int i;
	long m;

	/* compute and add miller-madow correction */
	for (m = 0, i = 0; i < 256; i++) {
		if (dist[i] > 0)
			m++;
	}

	return ( e + (((entropy_t)m - 1.0) / (entropy_t)(msglen * 2)) / log_nat_2);
}

entropy_t compute_jk_entropy(entropy_t e, unsigned long *dist, size_t msglen)
{
	entropy_t jke;
	entropy_t jksum;
	int i;

	jksum = 0.0;
	for (i = 0; i < 256; i++) {
		if (dist[i] > 0) {
			dist[i]--;
			COMP_ENT(dist, msglen - 1, jke);
			dist[i]++;
			jksum += (entropy_t)(dist[i]) * jke;
		}
	}
	jksum = jksum * ((entropy_t) (msglen - 1)) / (entropy_t) (msglen);

	return ((entropy_t)(msglen) * e - jksum);
}

entropy_t compute_pan_entropy(entropy_t e, unsigned long *dist, size_t msglen)
{
	return (e + paninski_bias( (entropy_t)msglen / 256.0 ));
}

entropy_t paninski_bias(long double c)
{ /* Computes
	-log c + e^-c sum_{j>=1} c^j/j! log (j+1)
  */
	long double z, ec, cjj, zz;
	int j;
	entropy_t ret;

	z = 0.0;
	cjj = c;
	for (j=1;;) {
		zz = z + cjj * logl ((long double)(j+1));
		if (zz==z)
			break;
		j++;
		cjj *= c / (long double)j;
		z = zz;
	}
	ec = expl (-c);
	z *= ec;
	z -= logl (c);

	ret = z / logl (2.0);

	return (ret);
}
