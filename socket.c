/*
* NetAnalyzer -multithreaded portable statefull Network passive analyzer
* Project page: http://code.google.com/p/netanalyzer/
* Author: Elie Bursztein LSV, ENS-Cachan, CNRS, INRIA
* Email: elie@bursztein.eu
* Licence: GPL v2 
*
* netAnalyzer is (C) Copyright 2008  by Elie Bursztein 
*/
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "headers/function.h"
#include "headers/structure.h"
#include "headers/constant.h"


extern	t_option	option;
        fd_set 		active_fd_set, read_fd_set;

int handle_client_request (int fd)
{
    char buffer[MAXMSG];
    int nbytes;
    
    bzero(buffer, MAXMSG);
    nbytes = read (fd, buffer, MAXMSG);
    //closing out my closet
    if (nbytes <= 0 || atoi(buffer) == QUIT)
         return -1;
    //FIXME:need to handle client change such as : what to print, time intervall and may be the file to read (sic :()
    return 0;
}

int make_socket(short int port)
{
	int sock,reuse=1;
	struct sockaddr_in name;
	/*Createthesocket.*/
	sock = socket(PF_INET, SOCK_STREAM,0);
	if(sock < 0)
            die("error creating socket");
	/*Givethesocketaname.*/
	name.sin_family=AF_INET;
	name.sin_port=htons(port);
	name.sin_addr.s_addr=htonl(INADDR_ANY);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,(int*)&reuse, sizeof(reuse));
	if(bind(sock, (struct sockaddr*)&name, sizeof(name)) < 0)
		die("can't bind port");
	return sock;
}


void launch_deamon(void)
{
	int sock, newsock, size, i;
	struct sockaddr_in clientname;
	
	
	/*Create the socket and set it up to accept connections.*/
	sock = make_socket(option.deamon);
	if(listen(sock, 1) < 0)
            die("can't make the socket listen");
	/*Initialize the set of active sockets.*/
	FD_ZERO(&active_fd_set);
	FD_SET(sock, &active_fd_set);
	while(1)
	{
	    //FIXME when do we return ?
            /*Block until input arrives on one or more active sockets.*/
            read_fd_set = active_fd_set;
            //FIXME:Replace Select by the specific poll of architecture (more effective)
            if(select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0)
                exit(EXIT_FAILURE);
            /*Service all the sockets with input pending.*/
            for(i = 0; i < FD_SETSIZE; ++i)
            {
                if(FD_ISSET(i, &read_fd_set))
                 {
                    if(i == sock) 
                    {
                        /*Connection request on original socket.*/
                        //FIXME:Need authentication for client and maybe some crypto and compression
                        size=sizeof(clientname);
			newsock = accept(sock, (struct sockaddr*)&clientname,(socklen_t *)&size);
                        if(newsock < 0)
                            die("Error when accepting a client");
                        FD_SET(newsock , &active_fd_set);
                    } else {
                        /*Data arriving on an already -connected socket.*/
                        if(handle_client_request(i) < 0) 
                        {
                            close(i);
                            FD_CLR(i,&active_fd_set);
                        }
                    }
                }
            }
        }
}

