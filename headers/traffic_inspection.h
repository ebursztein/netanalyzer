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
 *	\file traffic_inspection.h
 *	\brief Traffic inspection structures, constants, functions.
 *
 *	This file is used to regroup all the informations used for the traffic inspections.
 *	Structure live here because they are too many to fit in the main structure.h
 *	Except s_software which is located to structure.h because it's on of the main
 *	Analysis offer by the analyzer.
 *	\author  Elie
 *	\version 1.1
 *	\date    Dec 2006
 */
 
#ifndef _TRAFF_INSPECT_H
#define _TRAFF_INSPECT_H
#include <pcap.h>
//#include "structure.h"

typedef double entropy_t;



//###########Structures#####################

/*
typedef struct s_info {


	char	traffic_nature[64]; ///!< what sort of traffic it is ? file transfert, automatic information, interactive ?
	char	traffic_type[64]; ///!< what sort of file does this traffic send
	char	traffic_category[64];	///!< what category this traffic fall under ?

} t_info;
*/
/*

typedef struct s_traffic_pattern {
	_u32		
} t_traffic_pattern;
*/


/*!
\struct s_traffic_profile
 \brief used to store trafic profil informations used in the traffic inspection engine 
 
 used to store discriminator such as timmimg, len, entropy, mean  and so on.
 */
 
 typedef struct s_traffic_profile {
	 _u64			nb_pkt;
	 _u64			len_total;
	 _u64			pkt_len_mean;
	 unsigned long		freq[256];
	 entropy_t		shannon_entropy;
	 entropy_t		miller_madow_entropy;
	 entropy_t		jackknifed_entropy;
	 entropy_t		paninski_entropy;
	 entropy_t		miller_madow_entropy_bias;
	 entropy_t		jackknifed_entropy_bias;
	 entropy_t		paninski_entropy_bias;
	 _s64			timing_intervall;
	 _s64			timing_response;
 } t_traffic_profile;
 
 
 //############Functions####################

 //init function
 void 	services_init(void);
 
 //Traffic engine entry point
 void 	traffic_analyze(t_session *s, t_pkt *p);

 void	traffic_phase_feedback(t_session *s, t_pkt *p, _u8 next_phase);
 void	traffic_analyze_stat(t_session *s, t_pkt *p, _u8 host, _u8 type);
 int  	traffic_ttl_distance(_u8 ttl, char *os, char* version);
 void	traffic_mtu_packet(t_pkt *p);

 
//procotol detection

void detection_new_port(t_session *s, char *protocol_name, _u32 guess_probability);
void detection_protocol_pattern(t_session *s, t_pkt *p, char *protocol_name, _u32 guess_probability);


 
 // Entry point for traffic pattern analysis
 void 	analyze_traffic_pattern(t_session *s, t_pkt *p);
 void 	traffic_pattern_match_packet_protocol(t_session *s, t_pkt *p);
 void 	traffic_pattern_match_packet_software(t_session *s, t_pkt *p, _u8 type);
 void 	traffic_pattern_match_packet_file(t_session *s, t_pkt *p);
 void 	traffic_pattern_match_packet_user(t_session *s, t_pkt *p);
 void 	traffic_pattern_match_packet_user2user(t_session *s, t_pkt *p);


 
//Profiling traffic
//profile
 void 	traffic_analyze_by_profile(t_session *s, t_pkt *p);
 void 	traffic_profile_dump(t_session *s, t_pkt *p);

//Entropy function
 entropy_t compute_mm_entropy(entropy_t e, unsigned long *dist, size_t msglen);
 entropy_t compute_jk_entropy(entropy_t e, unsigned long *dist, size_t msglen);
 entropy_t compute_pan_entropy(entropy_t e, unsigned long *dist, size_t msglen);
 entropy_t paninski_bias(long double c);

//############Macro####################
/*!
* \brief Entropy macro by Julien Olivain
* \author Julien Olivain
*
* used tas discriminator
*/
#define log2of10 3.32192809488736234787
#define log_nat_2 0.69314718055994530942
# define log2(x)     (log2of10 * log10(x))

#define COMP_ENT(stats,size,entropy)                     \
do {                                                     \
  int i;                                                 \
  entropy_t byteprob;                                    \
  unsigned long *s;                                      \
                                                         \
  (entropy) = 0.0;                                       \
  for (s = (stats), i = 0; i < 256; i++, s++) {          \
    if (*s) {                                            \
      byteprob = (entropy_t) (*s) / (entropy_t)(size);   \
      (entropy) += byteprob * log2(1.0 / byteprob);      \
}                                                    	\
}                                                     	 \
} while (0)
#endif
