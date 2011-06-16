/*
 *  $Id: libnet_helper.c,v 1.1.1.1 2005/03/06 00:39:15 weiming_lai Exp $
 *
 *  libnet_helper.c - help to create libnet instance
 *
 *  Copyright (c) 2005 weiming lai <weiminglai@hotmail.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "arpspoof.h"
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#ifndef LIBNET_INJECTION_TYPE
#define LIBNET_INJECTION_TYPE   LIBNET_LINK
#endif

static libnet_t* gLibnetPtr = NULL;

/* local function declaration */
int selectInterface(char* ifName, size_t size);

void destroyLinkInstance()
{
    if (gLibnetPtr)
	{
        libnet_destroy(gLibnetPtr);
		gLibnetPtr = NULL;
	}
}

libnet_t *createLinkInstance(char* ifName)
{	
	char     errbuf[LIBNET_ERRBUF_SIZE];

	if (gLibnetPtr)
		destroyLinkInstance();
			
    gLibnetPtr  = libnet_init(
                       LIBNET_INJECTION_TYPE,      /* injection type */
                       ifName,                   /* network interface */
                       errbuf);                  /* errbuf */	
	if (! gLibnetPtr)
		fprintf(stderr, "%s", errbuf);
	return gLibnetPtr;
}

libnet_t *getLinkInstance(int allowSelect)
{
	char     ifname[IF_NAME_SIZE];
	char     errbuf[LIBNET_ERRBUF_SIZE];

	if (gLibnetPtr)
		return gLibnetPtr;	
	else if (allowSelect)
	{		     
		if (selectInterface(ifname, IF_NAME_SIZE-1) != 0)
  	    {
		   fprintf(stderr, "failed to find the interface\n");
		   return NULL;
	    }	    
        gLibnetPtr  = libnet_init(
                       LIBNET_INJECTION_TYPE,    /* injection type */
                       ifname,                   /* network interface */
                       errbuf);                   /* errbuf */
		if (! gLibnetPtr)
		   fprintf(stderr, "%s", errbuf);
	}
	return gLibnetPtr;
}

int selectInterface(char* ifName, size_t size)
{
    pcap_if_t *alldevs, *d;
	int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	    
  	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}		
	printf("Select the interface number:\n");
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{		
		if (d->description)
			printf("%d. %s\n", ++i, d->description);
		else
			printf("%d. %s\n", ++i, d->name);
	}
		
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure Pcap is installed.\n");
		return -1;
	}
		
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
		
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);    
	if (strlen(d->name) > size)
	{
		printf("\nbuffer size(%d) is too small, the minimal size is %d.\n", size, strlen(d->name));
		/* Free the device list */
		return -1;
	}
	memcpy(ifName, d->name, strlen(d->name)+1);
	return 0;
}

/* EOF */