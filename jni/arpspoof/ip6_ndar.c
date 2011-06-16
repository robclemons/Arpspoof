/*
 *  $Id: ip6_ndar.c,v 1.1.1.1 2005/03/06 00:39:12 weiming_lai Exp $
 *
 *  ip6_ndar.c - construct ipv6 neighbor discovery address resolution pkt
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

#include "string.h"
#include "arpspoof.h"
#include "libnet_helper.h"

int 
isHex(char c)
{
	if ( c >= '0' && c <='9' ||
		c >= 'a' && c <='f' ||
		c >= 'A' && c <='F')
		return 1;
	return 0;
}

int
in6_is_addr_linklocal(in6_addr_t *a)
{
    return ((a->libnet_s6_addr[0] == 0xfe) &&
            ((a->libnet_s6_addr[1] & 0xc0) == 0x80));
}

int
in6_is_addr_multicast(in6_addr_t *a)
{
    return (a->libnet_s6_addr[0] == 0xff);
}

int
in6_is_addr_sitelocal(in6_addr_t *a)
{
    return ((a->libnet_s6_addr[0] == 0xfe) &&
            ((a->libnet_s6_addr[1] & 0xc0) == 0xc0));
}

/* Checksum a block of data */
u_int16_t 
csum(u_int16_t *packet, int packlen) 
{
	register unsigned long sum = 0;

	while (packlen > 1) {
		sum+= *(packet++);
		packlen-=2;
	}

	if (packlen > 0)
		sum += *(unsigned char *)packet;

	/* TODO: this depends on byte order */

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (u_int16_t) ~sum;
}

u_int16_t 
icmp6csum(in6_addr_t *src, in6_addr_t *dst, 
		  u_char *i_pkt, u_int32_t i_len,
		  u_char *p_pkt, u_int32_t p_len) 
{	
	struct ipv6_pseudo_hdr phdr;
    u_int16_t              chksum;

	/* Make sure tempbuf is word aligned */
	u_int16_t *buf = (u_int16_t *)malloc(sizeof(phdr)+ i_len + p_len);
	u_int8_t *tempbuf = (u_int8_t *)buf;	
	if(tempbuf == NULL) {
		fprintf(stderr,"Out of memory: ICMP checksum not computed\n");
		exit(-1);
	}
	memcpy(tempbuf+sizeof(phdr), i_pkt, i_len);
	if (p_len)
	{
		memcpy(tempbuf+sizeof(phdr)+i_len, p_pkt, p_len);
	}

	/* do an ipv6 checksum */
	memset(&phdr, 0, sizeof(phdr));
	memcpy(&phdr.source, src, sizeof(in6_addr_t));
	memcpy(&phdr.destination, dst, sizeof(in6_addr_t));
	phdr.ulp_length = htonl(i_len+p_len);
	phdr.nexthdr = IPPROTO_ICMPV6;	
	memcpy(tempbuf, &phdr, sizeof(phdr));
	
	chksum = csum(buf,sizeof(phdr)+i_len+p_len);
	free(buf);
	return chksum;
}

void
get_ip6_msna(in6_addr_t *ip6addr, in6_addr_t *mcast)
{
	u_char msa_addr[]= {0xff, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
		                 0x0,  0x0, 0x0, 0x1, 0xff,0x0, 0x0, 0x0};
	u_char* t_addr = (u_char*) ip6addr;

	memcpy(&msa_addr[13], &t_addr[13], 3);	
	memcpy((u_char *)mcast, msa_addr, 16);	
}

int
ipv6_name_resolve(char* name, in6_addr_t* ip6addr)
{
	u_char*   pa = (u_char *)ip6addr;
	u_int32_t t_addr[]= {0,0,0,0,0,0,0,0};
	u_char    f_addr[40]= {0};
	int     i, dsign, ssign, ltok;

	ltok = ssign = 0;
	dsign = -1;

	for(i=0; i < strlen(name); i ++)
	{
		if (name[i] == ' ')
			break;
		if(name[i] ==':')
		{
			if(ltok== ':')
			{
				/* only allow one :: */
				if (dsign != -1)
					return -1;
				dsign = i-1;	
				ltok = 0;
				continue;
			}
			else
			{
				/* not allow :xxx  */
				if (i == 0 && name[1] != ':')
					return -1;				
			}
		}
		else if ( !isHex(name[i]))
			  return -1;
		else if (ltok == ':')
			  ssign ++;
		ltok = name[i];
	}

	if (dsign == -1 && ssign < 7 ||
		ssign > 7 ||
		dsign != -1 && ssign > 4)		
		return -1;

	/* form a formal ipv6 address: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx */
	if (ssign == 7)
		strncpy((char *)f_addr, name, i);
	else
		if (dsign == 0)
		{
			for (i=0; i < 7 - ssign; i++)
				strcat((char *)f_addr, "0:");
			strcat((char *)f_addr, (char *)&name[dsign+2]);
		}
		else
		{
			strncat((char *)f_addr, (char *)name, dsign);
			strcat((char *)f_addr, ":");
			for (i=0; i < 6 - ssign; i++)
				strcat((char *)f_addr, "0:");
			if(name[dsign+2] == '\0')
			   strcat((char *)f_addr, "0");
		    else
			   strcat((char *)f_addr, &name[dsign+2]);
		}

	sscanf((char *)f_addr, "%x:%x:%x:%x:%x:%x:%x:%x", 
		&t_addr[0], &t_addr[1], &t_addr[2], &t_addr[3],
		&t_addr[4], &t_addr[5], &t_addr[6], &t_addr[7]);

	for (i=0; i < 8; i ++)
	{
		pa[2*i]   = (u_char)((t_addr[i] >> 8) & 0xff);
		pa[2*i+1] = (u_char)((t_addr[i]) & 0xff);
	}
	return 1;
}

int
ipv6_find_mac(in6_addr_t addr, u_char* mac)
{
	u_char* mac_addr = (u_char *)&addr;
	libnet_t* l;

	if (in6_is_addr_linklocal(&addr))
	{
	   mac[0] = mac_addr[8] & 0xfd; /* remove the 'u' bit */
	   mac[1] = mac_addr[9];
	   mac[2] = mac_addr[10];
	   mac[3] = mac_addr[13];
	   mac[4] = mac_addr[14];
	   mac[5] = mac_addr[15];
	   return 1;
	}
	else
	{
		l = getLinkInstance(0);
		if (l && 0 == find_neighbor_mac(l, addr, mac))
			return 1;
	}
	return 0;
}

libnet_ptag_t 
build_icmp6_ndr(
in6_addr_t s_ip6, in6_addr_t d_ip6,
u_int8_t type, u_int8_t code, u_int16_t sum,
u_int8_t *payload, u_int32_t payload_s,
libnet_t *l, libnet_ptag_t ptag)
{
	u_int32_t n, h;
    libnet_pblock_t *p;	
    struct libnet_icmpv6_hdr icmp6_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = LIBNET_ICMPV6_H + payload_s;        /* size of memory block */
    h = LIBNET_ICMPV6_H + payload_s;        /* hl for checksum */

	/*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, 0x41);
    if (p == NULL)
    {
        return (-1);
    }
	memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
    icmp6_hdr.icmp_type  = type;             /* packet type */
    icmp6_hdr.icmp_code  = code;             /* packet code */

	if (type == NDOP_ADVERTISE)
	     icmp6_hdr.id = htons(0x6000);
    icmp6_hdr.icmp_sum   = icmp6csum(&s_ip6, &d_ip6, 
		                            (u_char*) &icmp6_hdr, sizeof(icmp6_hdr),
									 payload, payload_s); /* checksum */    

    n = libnet_pblock_append(l, p, (u_int8_t *)&icmp6_hdr, LIBNET_ICMPV6_H);
    if (n == -1)
    {
        libnet_pblock_delete(l, p);
        return (-1);
    }

    if ((payload && !payload_s) || (!payload && payload_s))
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			     "%s(): payload inconsistency\n", __func__);
        libnet_pblock_delete(l, p);
        return (-1);
    }
 
    if (payload && payload_s)
    {
        n = libnet_pblock_append(l, p, payload, payload_s);
        if (n == -1)
        {
            libnet_pblock_delete(l, p);
            return (-1);
        }
    } 
    return (ptag ? ptag : libnet_pblock_update(l, p, h,0x41));
}

libnet_ptag_t
build_ndar(in6_addr_t spa, in6_addr_t tpa, int op, int optlen, u_char *opt,
		   libnet_t *l)
{
	u_char        pkt[60];
	int           tlen = optlen + sizeof(in6_addr_t);
    in6_addr_t    m_dst;
	libnet_ptag_t t;

	if (op == NDOP_SOLICATION)
	{
	   /* use multicast solicited node address */
	   get_ip6_msna(&tpa, &m_dst);	
	   memcpy(pkt, &tpa, sizeof(in6_addr_t));
	}
	else
		memcpy(pkt, &spa, sizeof(in6_addr_t));

	memcpy(&pkt[sizeof(in6_addr_t)], opt, optlen);	

	t = build_icmp6_ndr(spa, (op == NDOP_SOLICATION)? m_dst : tpa, 
		    op, 0, 0, pkt, tlen, l, 0);

	if (t == -1)
    {
        fprintf(stderr, "Can't build ICMP6 header: %s\n", libnet_geterror(l));
        return -1;
    }
	return libnet_build_ipv6(0,0,(u_int16_t)tlen+sizeof(struct libnet_icmpv6_hdr),
		              IPPROTO_ICMP6, 255, spa, 
					  (op == NDOP_SOLICATION)? m_dst : tpa, 
					  NULL, 0, l, 0);	
}

int
ndar_send(libnet_t *l, int op, u_char *sha, in6_addr_t spa, u_char *tha, in6_addr_t tpa)
{
	libnet_ptag_t t;
	u_char        pkt[60];	
	u_char        dmac[]={0x33,0x33,0xff,0x00,0x00,0x00};
			
	if (sha == NULL &&
	    (sha = (u_char *)libnet_get_hwaddr(l)) == NULL) {
		return (-1);
	}
	if (tha == NULL)
	{		
		memcpy(&dmac[3], &tpa.libnet_s6_addr[13], 3);
		tha = dmac;
	}	
	if (op == NDOP_SOLICATION)
	   pkt[0] = 1;  /* icmp6 solicition msg opt: source link-layer addr */
	else	
		pkt[0] = 2; /* icmp6 solicition msg opt: target link-layer addr */	
	pkt[1] = 1;     /* icmp6 msg opt len */
	memcpy(&pkt[2], sha, 6);

    libnet_clear_packet(l);
	t = build_ndar(spa, tpa, op, 8, pkt, l);
	if (t == -1)
    {
        fprintf(stderr, "Can't build NDAR header: %s\n", libnet_geterror(l));
        return -1;
    }

	t = libnet_autobuild_ethernet(
            tha,                                    /* ethernet destination */
            0x86dd,                                 /* IPv6 */
            l);                                     /* libnet handle */

    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        return -1;
    }
    return libnet_write(l);    		
}
/* EOF */
