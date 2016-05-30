/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
/*
 * Contains the functions used by netprof
 */
#ifndef _FUNCTION_H
#define _FUNCTION_H 1

#include <pcap.h>
#include <assert.h>
#include "structure.h"

// displaying the help
void    usage();
//post comamnd line arg parsing initialisation (hashtable and so on)
void 	post_parsing_init();
//portable dup
char 	*my_strndup(char *str, unsigned int n);
//secure malloc
void 	*xmalloc(size_t size);
//Cstring unescape
char 	*cstring_unescape(char *str, unsigned int *newlen);
//boyer moore matching algorithm
int 	match(char *x, int m, char *y, int n);
//used to initializing the variables
void	setup_default();
//using the args to make a pcap filter
char    *make_filter_from_trailing_args(int, char **);
//anti evasion
t_pkt 	*anti_evasion(t_pkt *entry);
//chunk matching
t_chunk chunk(char *str, char *begin, char *end);
//chunk n car matching
//t_chunk chunkn(char *str, char *begin, char *end, int len);
//for opening the pcap
pcap_t  *open_pcap(char *, int, int, char *);
//function for init termcaps if usefull
void	init_fancy();
//testing if in a ip is a broadcast
_u8	ip_is_broadcast(_u32 ip);
//detect gateway
void 	gateway_detect();
//calculate crc : dan berstein djb2 algo
_u64	crc(char  *str);
// Benchmark function
void benchmark(_s32 t);


//compatiblity joy
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
int getline(char** line, size_t* size, FILE* fp);
#endif

//threads funtions

//the collector main
void collector_function(void);
//decoder
void decoder_function(void);
//stateful
void stateful_function(void);
//traffic
void traffic_function(void);
//application
void application_function(void);
//the output
void output_function(void);


//fifo handling
void	fifo_add_col(char *buf, unsigned int len, long t, long time_usec);
int 	fifo_need_swap_col();
void 	fifo_swap_col();
int	fifo_size_col();
int 	fifo_col_ready();
void 	fifo_col_readover();


t_pkt 	*fifo_next_dec();
int 	fifo_need_swap_dec();
void 	fifo_swap_dec();
int	fifo_size_dec(); 

t_pkt 	*fifo_next_stat();
int 	fifo_need_swap_stat();
void 	fifo_swap_stat();
int	fifo_size_stat(); 

t_pkt 	*fifo_next_traf();
int 	fifo_need_swap_traf();
void 	fifo_swap_traf();
int	fifo_size_traf(); 

t_pkt 	*fifo_next_app();
void fifo_free_app();

//pkt handling
t_pkt* new_packet(char *buf, unsigned int len, int num, long t, long time_usec);
t_pkt* add_packet_in_list(char *buf, unsigned int len, int num, long t, long time_usec);
t_pkt*	swap_packet_list();
t_pkt*	swap_decoded_packet_list();
int 	free_packet_list(t_pkt *lst);
void	free_packet(t_pkt *p);

//Protocols
void 	free_http(t_pkt *entry);
void	free_ftp(t_pkt	*entry);
void	free_pop3(t_pkt	*entry);
void	free_imap(t_pkt	*entry);
void	free_ssh(t_pkt	*entry);
void	free_smtp(t_pkt	*entry);
void	free_mysql(t_pkt	*entry);
//decoding protocol
t_pkt	*decode_ether(t_pkt *entry);
t_pkt	*decode_arp(t_pkt *entry);
t_pkt	*decode_ip(t_pkt *entry);
t_pkt	*decode_tcp(t_pkt *entry);
t_pkt	*decode_icmp(t_pkt *entry);
t_pkt	*decode_udp(t_pkt *entry);
t_pkt	*decode_http(t_pkt *);
t_pkt	*decode_dhcp(t_pkt *);
t_pkt	*decode_dns(t_pkt *);
t_pkt	*decode_ftp(t_pkt *);
t_pkt	*decode_pop3(t_pkt*);
t_pkt	*decode_imap(t_pkt*);
t_pkt 	*decode_ssh(t_pkt *);
t_pkt	*decode_smtp(t_pkt *);
t_pkt	*decode_mysql(t_pkt *);
t_pkt 	*decode_dumb(t_pkt*);


//output common function
//unified output function 
int out(char *str, ...);
void warning(char *err, ...);
void die(char *err, ...);
void output_trafic(int value, char* buf);
void output_trafic_by_sec(int value, char *buf);
int output_value_by_sec(int value);





//hash function for data structs
int init_hash(void);
int add_hash(t_hash *list, _u32 key, t_hash_entry *data);
int del_hash(t_hash *list, _u32 key, t_hash_entry *data);
_u32 hash_indexFor(_u32 tablelength, _u32 hashvalue);


//session functions
_s32 analyze_session(t_pkt *p);
t_hash *session_init();
_u32 session_is_equal(t_session *s1, t_session *s2);
void session_make_array();
void session_output(_u8 type, _s32 limit);
void session_clean();

//protocol functionc
_u32 analyze_protocol();
void protocol_init();
//Sort the hash table for displaying and stating
void protocol_stating();
void protocol_output(_u8 type, _s32 limit);
void protocol_clean();


//host functions
_u32 		analyze_host(t_pkt *p, _u8 update);
t_hash 		*host_init();
_u32		host_is_equal(t_host *h1, t_host *h2);
void		host_sorting();
void		host_output(_u8 type, _s32 limit);
void		host_clean();
void 		host_set_option(_u32 ip, _u32	opt);

//software functions
_u32 		analyze_software(t_software *o);
t_hash 		*software_init(void);
void 		software_sorting();
void 		software_output(_u8 type, _s32 limit);
void 		software_clean();
void		software_add_pattern_match(_u32 ip, _u16 port, _s32 proto, char *servicename, char *product, char *version, char *info, char *hostname, char *ostype, char *devicetype, _u8 type);
void 		software_session_display_plain(t_session *s);
void 		software_session_display_xml(t_session *s);
void		software_display_plain(t_software *o, _u8 type);
//user functions
_u32 		analyze_user(t_user *u);
t_hash 		*user_init(void);
void 		user_sorting();
void 		user_output(_u8 type, _s32 limit);
void 		user_clean();
void 		user_session_display_plain(t_session *s);
void 		user_session_display_xml(t_session *s);			
		
		
//user functions
_u32 		analyze_user2user(t_user_to_user *u);
t_hash 		*user2user_init(void);
void 		user2user_sorting();
void 		user2user_output(_u8 type, _s32 limit);
void 		user2user_clean();
void 		user2user_session_display_plain(t_session *s);		
void 		user2user_session_display_xml(t_session *s);		

//error functions
t_hash 		*error_init(void);
int 		analyze_error(t_session *sess, t_pkt *p, _u64 s, _u64 h, _u32  ip, _u8 type, _u8 layer, char *class, char *name, char *group, char  *details, char *target, _s64 last_time, _s64 last_time_usec);
int 		analyze_error_pkt(t_session *sess, t_pkt *p, _u64 s, _u64 h);
void 		error_sorting();
void 		error_output(_u8 type, _s32 limit);
void 		error_clean();
void 		error_session_display_plain(t_session *s);	
void 		error_session_display_xml(t_session *s);
int 		error_display_plain(t_error *e, _u8 type);

//live dump
void livedump_display_error(t_error *e, t_pkt *p, t_session *s);
void livedump_display_newsess(t_session *s);	
		



//mac prefix
t_hash *macprefix_init(void);
void macprefix_add(int prefix, char* vendor);
void macprefix_list();
char *macprefix_get_vendor_by_arp(_u8 *arp);

//Parsing function
int parse_conf(char *file_name);
int parse_traffic_pattern(FILE *fp, int l);
int parse_main_block(FILE *fp, int l);
int parse_tuning_block(FILE *fp, int l);
int parse_analyze_block(FILE *fp, int l);
int parse_services_block(FILE *fp, int l);
int parse_macprefix_block(FILE *fp, int l);
_u8 parse_is_option_affect_op(char *c);
_u8 parse_is_comment(char *c);

#endif
