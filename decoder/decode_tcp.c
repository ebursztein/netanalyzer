/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include "../headers/structure.h"
#include "../headers/constant.h"
#include "../headers/function.h"
#include "../headers/protocol.h"

extern	t_option option;

t_pkt		*decode_tcp(t_pkt *entry)
{
	_u16	hl;
        _u8	*options;
        _u8	kind;
        _u8	len;
        _s32	i;
        regex_t regex;
        _s32 reti;

	if ((entry->len - entry->decoded_len) < TCP_MIN_HLEN)
	{ 
		entry->pkt_proto = TCP_TRUNKED; 
      		return entry;
    	}

  	entry->tcp = (t_tcp *)(entry->buf + entry->decoded_len);
  	//tcp len
        hl = entry->tcp->doff >> 2;
        //printf("hl %d\n",hl);
        //printf("hl2 %d\n",  entry->tcp->doff *4);
  	

  	if (hl > TCP_MAX_HLEN)
    	{
		entry->pkt_proto = TCP_OVERLEN;
      		return entry;
    	}
	
        entry->pkt_proto = TCP;
        //TCP options parsing
        //FIXEME:Some ops are missing
        entry->tcp_opt = malloc(sizeof(t_tcp_opt));
        bzero(entry->tcp_opt, sizeof(t_tcp_opt));
        i = 0;
	//disabling the tcp option parse
	//checking if there is option ntoh usefull ??
	if (hl > 200) 
        {
	    options = (_u8 *)(entry->buf + entry->decoded_len + 20);
            kind = *(options + i);
            while (kind != 0 && i <= hl - 20) 
            {
                switch (kind) {
                case 1:
                    i++;
                    break; // NOP byte
                case 2:
              //      i += 2;
               //    entry->tcp_opt->mss = (_u16)(options + i);
                    i += 2;
                    break;
                case 3:
                    i += 2;
                   // entry->tcp_opt->wss = (_u16)(options + i++);
                    break;
                case 4:
                  //  i += 2;
                 //   entry->tcp_opt->sack_permitted = 1;
                    break;
                case 5:
                    i++;
                    len = (*options + i) - 1;
                    i += len;
                    break;
                case 6:
                    i += 2;
                    entry->tcp_opt->tcp_echo = (_u32) (options + i);
                    i += 4;
                    break;
                case 7:
                    i += 2;
                    entry->tcp_opt->tcp_echo_reply = (_u32) (options + i);
                    i += 4;
                    break;
                case 8:
                    i += 2;
		    entry->tcp_opt->ts = (_u32) (options + i);
                    i += 8;
                break;
                default:
                i++;
            }
            kind = *(options + i);
        }
    }
    entry->decoded_len += hl;
    //Payload len and pointer
    entry->payload = (char *)(entry->buf + entry->decoded_len);
    entry->payload_len = entry->len - entry->decoded_len;
    //sanity check
    if(!(entry->tcp->flags & TCP_URG) && entry->tcp->urp)
	    entry->sanity = entry->sanity | SANITY_TCP_LEAK;
    //leaking check
    if(entry->tcp->flags & TCP_ECE || entry->tcp->flags & TCP_ECE)
	    entry->sanity = entry->sanity | SANITY_TCP_UNUSED_FLAG;
    //T4 tcp finger print SYN, FIN, PSH, and URG
    if((entry->tcp->flags) & TCP_SYN && (entry->tcp->flags & TCP_FIN) && (entry->tcp->flags & TCP_PSH) && (entry->tcp->flags & TCP_URG))
	    entry->sanity = entry->sanity | SANITY_TCP_FINGER;
    //t7 FIN, PSH, and URG
    if((entry->tcp->flags) & TCP_FIN && (entry->tcp->flags & TCP_PSH) && (entry->tcp->flags & TCP_URG))
	    entry->sanity = entry->sanity | SANITY_TCP_FINGER;


    if (option.extfilter != NULL)
    {
        reti = regexec(&regex, (char *)(entry->buf + entry->decoded_len), 0, NULL, 0);
        /*if( !reti )
        {
              
                regfree(&regex);
        //if(strnstr((char *)(entry->buf + entry->decoded_len), option.extfilter, entry->len - entry->decoded_len) == 0)
        //FIXME: strlen of filter need on calculation not each tiem
        //if ((match((char *)(entry->buf + entry->decoded_len), (entry->len - entry->decoded_len), option.extfilter, strlen(option.extfilter))) == 0)
        } else {
            entry->pkt_proto = NOTDECODED;
            return entry;
        }*/
    }
  return entry;
}
