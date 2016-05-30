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
 *	\file collector_thread.c
 *	\brief 1st thread: used to read packets from network/file.
 *
 *	This file contain the 1st thread code used to collect packets.
 *	\author  Elie
 *	\version 3.0
 *	\date    2006
 */
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include "headers/structure.h"
#include "headers/constant.h"
#include "headers/function.h"


extern 	t_option 	option;
extern 	t_mutex		mutex;
extern	t_tuning	tuning;
extern	t_benchmark	bench;
struct pcap_stat*	ps;
_s32			datalink = 0;
t_pkt			*first = NULL;
t_pkt			*last = NULL;

void	collector_function(void)
{
  struct pcap_pkthdr	pp;
  pcap_t		*p;
  char			*buf;
  _u8			over = 0;
  int			i = tuning.fifo_size;
  ps = malloc(sizeof(struct pcap_stat));
  //int pcap_descriptor=-1; // -1 means we CANNOT select()
  // Opening the pcap
  if(option.debug == 2)
    printf("interface: %s, snaplen: %d, pcap timeout: %d, filter: %s extend filter: %s\n", option.interface, option.snaplen, option.pcaptimeout, option.filter, option.extfilter);
  p = open_pcap(option.interface, option.snaplen, option.pcaptimeout, option.filter);

  // Testes the link type and making adjustement
 if ( (datalink = pcap_datalink(p)) < 0)
   die("Cannot obtain datalink information: %s", pcap_geterr(p));

 switch(datalink) {
 case DLT_EN10MB:	option.interface_type	= PI_ETHER; break;
 case DLT_IEEE802:     	option.interface_type   = 22; break;
#ifdef __amigaos__
 case DLT_MIAMI: 	option.interface_type   = 16; break;
#endif
#ifdef DLT_LOOP
 case DLT_LOOP:
#endif
 case DLT_NULL:     	option.interface_type  = 4; break;
 case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
 case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
       option.interface_type = 16;
#else
       option.interface_type = 24; /* Anyone use this??? */
#endif
   break;
 case DLT_PPP: 
#ifdef DLT_PPP_BSDOS
 case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
 case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
 case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
       			option.interface_type = 4;
#else
#ifdef SOLARIS
       			option.interface_type = 8;
#else
       			option.interface_type = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
   break;
 case DLT_RAW: 		option.interface_type = 0; break;
 case DLT_FDDI:		option.interface_type = 21; break;
#ifdef DLT_ENC
 case DLT_ENC:		option.interface_type = 12; break;
#endif /* DLT_ENC */
#ifdef DLT_LINUX_SLL
 case DLT_LINUX_SLL:	option.interface_type  = 16; break;
#endif
 default:
   die("Pcap Error:  Unknown datalink type (%d)\n", datalink);
 }


 if (option.fname != NULL)
  {
	//FIXME : pcap filter return no packet... hang for ever	
	//READ BLOCK BY BLOCK
	while (!over)
	{
		// Lock the mutex used between the collector and the parser
		pthread_mutex_lock(&mutex.col2dec);
		while(!over && i && (fifo_col_ready()))
		{
			//WE READ THE FILE by block
			if ((buf = (char *)pcap_next(p, &pp)) == NULL)
			{
				over = 1;
				//force the last block to swap
				fifo_col_readover();
			}
			else {
				//this ugly  but can't think how to do it in an other way
				option.intervall = pp.ts.tv_sec - option.startime;
				if(bench.nbpkt == 1)
					bench.startime = option.startime = pp.ts.tv_sec;
				//last = add_packet_in_list(buf, pp.caplen, readedpacket, pp.ts.tv_sec, pp.ts.tv_usec);
				fifo_add_col(buf, pp.caplen, pp.ts.tv_sec, pp.ts.tv_usec);
				//if(option.debug == 1)
				//	printf("COLLECTOR OFF:\tpkt %d\n", readedpacket);
				i--;
			}
		}
		// Unlocks the mutex between the collector and the parser
		pthread_mutex_unlock(&mutex.col2dec);
		//fifo full let's handover
		sched_yield();
		i = tuning.fifo_size;
		//reset i
	//printf("blinkenlight\n");
  	}
	//FILE OVER
	if(option.debug == 2)
	printf("read file is over let's die\n");
	pcap_stats(p, ps);
	return;
  } else {
    //ONLINE MODE
    while(1)
    {

      // Reads the pcap queue
      if ((buf = (char *)pcap_next(p, &pp)) != NULL)
      {
	if(bench.nbpkt == 1)
		      bench.startime = option.startime = pp.ts.tv_sec;
        // Lock the mutex used between the collector and the parser
        pthread_mutex_lock(&mutex.col2dec);
	usleep(1000);
	fifo_add_col(buf, pp.caplen, pp.ts.tv_sec, pp.ts.tv_usec);
        // Unlocks the mutex between the collector and the parser
        pthread_mutex_unlock(&mutex.col2dec);
      }
    }
  }
}

pcap_t	*open_pcap(char *ifname, _s32 snaplen, _s32 timeout, char *filter)
{
  pcap_t			*p;
  char			errbuf[512];
  struct bpf_program	bp;
  struct in_addr		tmp;
  char			err_buff[PCAP_ERRBUF_SIZE];

  if (!ifname && !option.fname)
  {

    if ((ifname = pcap_lookupdev(errbuf)) == NULL)
      die(errbuf);
  }
  if (option.fname == NULL)
  {
    //user want to sniff
    // Does the user have the correct privilege ?
    if (getuid() != 0)
      die("Sorry live capture need root privileges. You still can use the offline mode");
    if ((p = pcap_open_live(ifname, snaplen, 1, timeout, errbuf)) == NULL)
      die( errbuf);
    if(option.setuid)
      if (setuid(option.setuid))
        die("can't drop privileges, uid specified not valid\n");
    if (option.debug)
      printf("User privilege sucessfully dropped to uid %d\n", option.setuid);
  } else {
    if ((p = pcap_open_offline(option.fname, errbuf)) == NULL)
      die(errbuf);
    option.intervall =-1;
  }
  if (pcap_lookupnet(ifname, &(option.netp), &(option.maskp), err_buff) == 0)
  {
    if (option.debug == 2) {
      tmp.s_addr = option.netp;
      printf("open_pcap: netp = %s\n", inet_ntoa(tmp));
      tmp.s_addr = option.maskp;
      printf("open_pcap: mask = %s\n", inet_ntoa(tmp));
    }
  }
  else
  {
    if (option.debug == 2)
      printf("pcap_lookupnet error : no ip configured on the NIC\n");
    option.netp = option.maskp = 0;
  }
  if (pcap_compile(p, &bp, filter, 0, 0) < 0)
    die("Can't compile pcap filter");
  if (pcap_setfilter(p, &bp) < 0)
    die("pcap_setfilter error");

#if defined(__NetBSD__) ||  defined(__OpenBSD__)
  int	x;
  x = 1;
  if (ioctl(pcap_fileno(p), BIOCIMMEDIATE, &x) < 0)
  {
    perror("ioctl BIOCIMMEDIATE");
    exit(1);
  }
#endif

  return (p);
}
