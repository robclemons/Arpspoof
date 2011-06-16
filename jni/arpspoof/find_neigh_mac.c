/*
 *  $Id: find_neigh_mac.c,v 1.1.1.1 2005/03/06 00:39:07 weiming_lai Exp $
 *
 *  find_neigh_mac.c - use pcap to find ipv6 neighbor's mac address
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

#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include <pcap.h>
#include "arpspoof.h"

/* local function declaration */
void get_ip6_lla(in6_addr_t *ip6addr, u_char *mac);
int  get_in6_locallink_addr(libnet_t* l, in6_addr_t* addr);
void set_nda_filter(pcap_t *fp, in6_addr_t dst, in6_addr_t src);
pcap_t* start_capture_ad(libnet_t *l, in6_addr_t dst, in6_addr_t src, u_char* mac);
int  verify_recv_pkt(const u_char* pkt_data, in6_addr_t dest, u_char* mac);
void stop_capture(pcap_t *fp);

void 
get_ip6_lla(in6_addr_t *ip6addr, u_char *mac)
{
	int i;
	u_char lla_addr[]= {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
		                 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    u_char eui64[]=    {0x00,  0x0, 0x0, 0xff,0xfe,0x0, 0x0, 0x0};

	for (i=0; i <3; i ++)
	{
		eui64[i] = mac[i];
		eui64[i+5] = mac[i+3];
	}
	eui64[0] |=0x2;
	for (i=0; i <8; i ++)	
		lla_addr[i+8] = eui64[i];
	memcpy(ip6addr, lla_addr, sizeof(in6_addr_t));
}

int get_in6_locallink_addr(libnet_t* l, in6_addr_t* addr)
{
	u_char* myMac  = (u_char *)libnet_get_hwaddr(l);
	if (! myMac) 
		return (-1);	
	/* use Link-Local address directly */
	get_ip6_lla(addr, myMac);
	return 0;
}

void set_nda_filter(pcap_t *fp, in6_addr_t dst, in6_addr_t src)
{
     char filter[FILTER_LEN];
	 struct bpf_program fcode;
	 bpf_u_int32 NetMask = 0xffffff;
	 
	 sprintf(filter, "icmp6 and greater 80");	             

	//compile the filter
	if(pcap_compile(fp, &fcode, filter, 1, NetMask) < 0)
	{
		fprintf(stderr,"\nError compiling filter: wrong syntax.\n");
		return;
	}
	//set the filter
	if(pcap_setfilter(fp, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter\n");
		return;
	}
}

pcap_t* start_capture_ad(libnet_t *l, in6_addr_t dst, in6_addr_t src, u_char* mac)
{
	pcap_t *fp;	
    char errbuf[PCAP_ERRBUF_SIZE];
	
	if ((fp= pcap_open_live(libnet_getdevice(l), 
		                    1514 /*snaplen*/,
							PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
							200 /*read timeout*/,							
							errbuf)
							) == NULL)
	{
			fprintf(stderr,"\nUnable to open the adapter.\n");
			return NULL;
	}
	set_nda_filter(fp, dst, src);
	return fp;		
}

void stop_capture(pcap_t *fp)
{
	pcap_close(fp);
}

int find_neighbor_mac(libnet_t* l, in6_addr_t addr, u_char* mac)
{
   int ret, i=0;
   in6_addr_t myAddr;
   pcap_t*    fp;
#if 0
   struct pcap_pkthdr *header;
#else
   struct pcap_pkthdr header;
#endif
   const u_char *pkt_data;

   get_in6_locallink_addr(l, &myAddr); 

   fp = start_capture_ad(l, addr, myAddr, mac);
   if (!fp)
	   return 1;
   do {	   
       if (0 > ndar_send(l, NDOP_SOLICATION, NULL, myAddr, NULL, addr))
	        return (1);
	   	//start the capture
#if 0
	    ret = pcap_next_ex( fp, &header, &pkt_data);	
	    if (ret < 0)
	          break;	
	    else if (verify_recv_pkt(pkt_data, addr, mac))
	    {
	       ret = 0;
	       break;
	    }
	    else
		   ret = 1;
#else
            pkt_data = pcap_next(fp, &header);
            if (pkt_data && verify_recv_pkt(pkt_data, addr, mac))
            {
                ret = 0;
                break;
           }
           else
                 ret = 1;           
#endif
#if !(__WIN32__)
         sleep(1);
#else
         Sleep(250);
#endif			
	}   
	while (i++ <3);
	if (fp)
	   stop_capture(fp);
	if (! ret) 
		return 0;
	return 1;
}

int verify_recv_pkt(const u_char* pkt_data, in6_addr_t dest, u_char* mac)
{    
    struct libnet_icmpv6_hdr* icmp6_hdr = (struct libnet_icmpv6_hdr *)
	                                      (pkt_data+LIBNET_ETH_H+ LIBNET_IPV6_H);
	u_char* target = (u_char*)icmp6_hdr+ LIBNET_ICMPV6_H; 

    if (icmp6_hdr->icmp_type == NDOP_ADVERTISE)
	{
	    if(0 == memcmp(target,(u_char*)&dest, sizeof(dest)))
		{
	       memcpy(mac, pkt_data+6, 6);
		   return 1;
		}
	}
	return 0;
}   

/* EOF */
