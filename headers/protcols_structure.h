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

   netprof - portable Network headers
   ----------------------------------

   An other file inspired by p0f, extended to be more generic.
*/

#ifndef _HAVE_PROTO_STRUCT_H
#define _HAVE_PROTO_STRUCT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "types.h"



//ETHERNET

#define ETHER_TYPE_IP           0x800
#define ETHER_TYPE_ARP          0x806
#define ETHER_HLEN              14
#define ETHER_ALEN              6

typedef struct                  s_ether_addr
{
  _u8                          o[ETHER_ALEN];
}                               t_ether_addr;

typedef struct                  s_ether
{
  _u8                          dhost[ETHER_ALEN];
  _u8                          shost[ETHER_ALEN];
  _u16                         type;
}                               t_ether;


//IP

#define IP_DF   		0x4000	/* dont fragment flag */
#define IP_MF   		0x2000	/* more fragments flag */
#define IP_FRAG_UNUSED   	0x1000	/* not use  */
#define IP_MAX_TTL              255
#define IP_MIN_HLEN             20
#define IP_MAX_HLEN             (15 * 4)
#define IP_ALEN                 4
#define IP_HL(Ip)               (((Ip)->vhl & 0x0f) * 4)
#define IP_PROTO_ICMP 		1
#define IP_PROTO_IGMP 		2
#define IP_PROTO_IP 		4
#define IP_PROTO_TCP 		6
#define IP_PROTO_UDP 		17

/*
 * The current recommended default time to live (TTL) for the
 * Internet Protocol (IP) [45,105] is 64.
 */
#define IP_RECOMMENDED_TTL      64

typedef struct	s_ip_addr
{
  _u32		s_addr;
}t_ip_addr;

typedef struct	s_ip
{
  _u8		vhl;		// Version + Internet Header Length
  _u8		tos;		// Type of Service
  _u16		len;		// Total length
  _u16		id;		// Identification
  _u16		fragoff;	// Fragmentation flags and Fragment Offset field
  _u8		ttl;		// Time to live
  _u8		p;		// Protocol
  _u16		sum;		// Header checksum
  _u32		src;		// Source Address
  _u32		dst;		// Destination address
}t_ip;

//ARP
#define ARP_HLEN	28
#define ARP_HRD_ETHER	1
#define ARP_OP_REQUEST	1
#define ARP_OP_REPLY	2

typedef struct		s_arp
{
  _u16			hrd;
  _u16			pro;
  _u8			hln;
  _u8			pln;
  _u16			op;
  _u8			sha[ETHER_ALEN];
  _u8			spa[IP_ALEN];
  _u8			tha[ETHER_ALEN];
  _u8			tpa[IP_ALEN];
}t_arp;


//UDP

#define UDP_HLEN                8

typedef struct	s_udp
{
	_u16	sport;	// Source port
	_u16	dport;	// Destination port
	_u16	ulen;	// Total length
        _u16	sum;	// Checksum
}t_udp;


//ICMP

#define ICMP_HLEN			4

#define ICMP_TYPE_ECHO_REPLY		0
#define ICMP_TYPE_UNREACHABLE		3
#define ICMP_TYPE_SOURCE_QUENCH		4
#define ICMP_TYPE_ECHO_REQUEST		8
#define ICMP_TYPE_TIME_EXCEEDED		11
#define ICMP_TYPE_PARAMETER_PROBLEM	12
#define ICMP_TYPE_DATAGRAM_CONV_ERROR	31

typedef struct	s_icmp
{
  _u8		type;
  _u8		code;
  _u16		cksum;
}t_icmp;

//TCP

#define	TCPOPT_EOL			0	/* End of options */
#define	TCPOPT_NOP			1	/* Nothing */
#define	TCPOPT_MAXSEG			2	/* MSS */
#define TCPOPT_WSCALE   		3	/* Window scaling */
#define TCPOPT_SACKOK   		4	/* Selective ACK permitted */
#define TCPOPT_TIMESTAMP        	8	/* Stamp out timestamping! */
#define TCP_MAX_WIN             	65535
#define TCP_MIN_HLEN            	20
#define TCP_MAX_HLEN            	(15 * 4)
#define TCP_OFF(Tcp)            	((((Tcp)->offx2 & 0xf0) >> 4) * 4)
#define TCP_FIN                 	0x01
#define TCP_SYN                		0x02
#define TCP_RST                 	0x04
#define TCP_PUSH                	0x08
#define TCP_PSH	                	0x08
#define TCP_ACK                 	0x10
#define	TCP_URG				0x20
#define TCP_ECE  			0x40
#define TCP_CWR 			0x80

/*
typedef struct echo_s {
    u_int32_t     data;
} echo_t; 

typedef struct timestamp_t {
  u_int32_t	ts;
  u_int32_t	ets;
} timestamp_t;

typedef struct maxseg_t {
    u_int16_t	maxsegsize;
} maxseg_t;

typedef struct window_shift_t {
  u_int8_t      shift;
} window_shift_t;

typedef struct tcp_opt {
  window_shift_t *wss;
  maxseg_t       *mss;
  timestamp_t    *ts;
  echo_t         *tcp_echo;
  echo_t         *tcp_echo_reply;
  u_int8_t       sack_permitted;
} t_tcp_opt;
*/

typedef struct s_tcp_opt {
  _u16 	wss;
  _u16	mss;
  _u32	ts;
  _u32	ets;
  _u32	tcp_echo;
  _u32	tcp_echo_reply;
  _u8	sack_permitted;
} t_tcp_opt;

typedef struct                  s_tcp 
{
  _u16                         sport;
  _u16                         dport;
  _u32                         seq; 
  _u32                         ack; 
  _u8                          doff;  
  _u8                          flags;
  _u16                         win;
  _u16                         sum;
  _u16                         urp;
} t_tcp;


//HTTP 

typedef struct s_http {
	_u8	request_method;
	char	*request_uri;
	_u8	os_type;
	char	*os_version;
	_u8	explorer_type;
	char	*explorer_version;
	char	*host;
	char	*accept_languages;
	char 	*banner;
} t_http;

/* #define DEBUG_HTTP */

#define HTTP_OPTIONS		1
#define HTTP_GET				2
#define HTTP_HEAD				3
#define HTTP_POST				4
#define HTTP_PUT				5
#define HTTP_DELETE			6
#define HTTP_TRACE			7
#define HTTP_CONNECT		8
#define HTTP_RESPONSE		9
#define HTTP_300				10
#define HTTP_400				11
#define HTTP_500				12
#define HTTP_200				13

#define OS_LINUX				1
#define OS_WINDOWS			2
#define OS_MACOS				3
#define OS_UNKNOWN			4

#define BROWSER_IE				1
#define BROWSER_KONQUEROR	2
#define BROWSER_LYNX			3
#define BROWSER_MOZILLA		4
#define BROWSER_OPERA			5
#define BROWSER_UNKNOWN		6

//DHCP 

typedef struct s_bootp {
	_u8		bp_op;          /* packet opcode type */
	_u8		bp_htype;       /* hardware addr type */
	_u8		bp_hlen;        /* hardware addr length */
	_u8		bp_hops;        /* gateway hops */
	_u32		bp_xid;         /* transaction ID */
	_u16		bp_secs;        /* seconds since boot began */
	_u16		bp_flags;       /* flags: 0x8000 is broadcast */
	struct in_addr  bp_ciaddr;      /* client IP address */
	struct in_addr  bp_yiaddr;      /* 'your' IP address */
	struct in_addr  bp_siaddr;      /* server IP address */
	struct in_addr  bp_giaddr;      /* gateway IP address */
	_u8		bp_chaddr[16];  /* client hardware address */
	_u8		bp_sname[64];   /* server host name */
	_u8		bp_file[128];   /* boot file name */
	_u8	        bp_vend[64];    /* vendor-specific area */
} t_bootp;

typedef struct s_lease {
  	_u32	lease;
} t_lease;

/* #define DEBUG_DHCP */

#define BOOTREQUEST             1
#define BOOTREPLY               2

#define HETHER_ADDR		1

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define         DHCPDISCOVER    1
#define         DHCPOFFER       2
#define         DHCPREQUEST     3
#define         DHCPDECLINE     4
#define         DHCPACK         5
#define         DHCPNAK         6
#define         DHCPRELEASE     7
#define         DHCPINFORM      8

/* Useful define options to print informations during debugging */
#define SUBNET_MASK		1
#define ROUTER			3
#define IP_DOMAIN_NAME		6
#define DOMAIN_NAME		15
#define BROADCAST_ADDR		28
#define IP_ADDR_LEASE_TIME	51
#define DHCP_MSG_TYPE 		53
#define DHCP_SRV_IP		54


/*
 *   Structure for query header.
 */
typedef struct s_dns_header 
{
	_u16	id;           /* query identification number */
	_u8	flags1;       /* first byte of flags */
	_u8	flags2;       /* second byte of flags */
	_u16	qdcount;      /* number of question entries */
	_u16	ancount;      /* number of answer entries */
	_u16	nscount;      /* number of authority entries */
	_u16	arcount;      /* number of resource entries */
} t_dns_header;


/*
 * Define constants based on rfc883
 */
#define PACKETSZ        512             /* maximum packet size */

/*
 * Currently defined opcodes
 */
#define QUERY           0x0             /* standard query */
#define IQUERY          0x1             /* inverse query */
#define STATUS          0x2             /* nameserver status query */

/*
 * Macros for subfields of flag fields.
 */
#define DNS_QR(np)      ((np)->flags1 & 0x80)         /* response flag */
#define DNS_OPCODE(np)  ((((np)->flags1) >> 3) & 0xF) /* purpose of message */
#define DNS_AA(np)      ((np)->flags1 & 0x04)         /* authoritative answer */
#define DNS_TC(np)      ((np)->flags1 & 0x02)         /* truncated message */
#define DNS_RD(np)      ((np)->flags1 & 0x01)         /* recursion desired */

#define DNS_RA(np)      ((np)->flags2 & 0x80)   /* recursion available */
#define DNS_AD(np)      ((np)->flags2 & 0x20)   /* authentic data from named */
#define DNS_CD(np)      ((np)->flags2 & 0x10) 	/* checking disabled by resolver */
#define DNS_RCODE(np)   ((np)->flags2 & 0xF)    /* response code */

/*
 * Currently defined response codes
 */
#define NOERROR         0               /* no error */
#define FORMERR         1               /* format error */
#define SERVFAIL        2               /* server failure */
#define NXDOMAIN        3               /* non existent domain */
#define NOTIMP          4               /* not implemented */
#define REFUSED         5               /* query refused */


/*
 *   FTP
 */
typedef struct s_ftp 
{
    _u32	type;
    char	*login;
    char	*pass;
    char	*file;
    char	*dir;
    char	*client;
}t_ftp;

#define FTP_BINARY	1
#define	FTP_CH_DIR	2
#define	FTP_CLIENT	3
#define	FTP_DIR		4
#define	FTP_PASS	5
#define	FTP_PASV	6
#define	FTP_PUT		7
#define	FTP_PWD		8
#define	FTP_RETR	9
#define	FTP_SIZE	10
#define	FTP_USER	11
#define	FTP_LIST	12
#define	FTP_RESP_100	13
#define	FTP_RESP_200	14
#define	FTP_RESP_300	15
#define	FTP_RESP_400	16
#define	FTP_RESP_500	17
#define	FTP_ABORT	18
#define FTP_NOOP	19
#define	FTP_MKDIR	20
#define FTP_RMDIR	21
#define FTP_DELETE	22
#define FTP_QUIT	23
#define FTP_NOTDECODED	24

/*
 *   POP
 */
typedef struct s_pop3 
{
    _u32	type;
    char	*login;
    char	*pass;
    _u32	msgnum;
}t_pop3;

#define POP3_NOTDECODED	1
#define POP3_STAT	2
#define POP3_LIST	3
#define POP3_RETR	4
#define POP3_DELE	5
#define POP3_NOOP	6
#define POP3_RSET	7
#define POP3_QUIT	8
#define POP3_UIDL	9
#define POP3_USER	10
#define POP3_PASS	11
#define POP3_APOP	12
#define POP3_TOP	13
#define POP3_RESP_OK	14
#define POP3_RESP_ERR	15

/*
 *	IMAP   
 */
typedef struct s_imap 
{
    _u32	type;
    char	*login;
    char	*pass;
    char	*mbox;
    _u32	msgnum;
}t_imap;

#define IMAP_NOTDECODED	1
#define IMAP_NOOP	2
#define IMAP_LOGIN	3
#define IMAP_CAPABILITY	4
#define IMAP_SELECT	5
#define IMAP_FETCH	6
#define IMAP_STORE	7
#define IMAP_CLOSE	8
#define IMAP_RESP_OK	14
#define IMAP_RESP_BAD	15

//SSH

typedef struct s_ssh {
	_u32 	type;
	char	*banner;
	
} t_ssh;

#define SSH_NOTDECODED	1
//SMTP

typedef struct s_smtp {
	_u32 type;
	char	*banner;
} t_smtp;

//MYSQL

typedef struct s_mysql {
	_u32 type;
	char	*banner;
} t_mysql;

#define	MYSQL_NOTDECODED	1
#endif /* ! _HAVE_PROTO_STRUCT_H */
