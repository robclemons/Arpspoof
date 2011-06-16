/*
 *  $Id: arpspoof.h,v 1.1.1.1 2005/03/06 00:39:03 weiming_lai Exp $
 *
 *  arpspoof.h - all arpspoof global settings & function prototypes  
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

#ifndef _ARPSPOOF_H_
#define _ARPSPOOF_H_

#if (HAVE_CONFIG_H)
#include "config.h"
#endif

#ifndef _WIN32
#include "libnet.h"
#else
#include "../libnet/include/win32/libnet.h"
#endif

#define MIN_ND_PKT_LEN 86
#define FILTER_LEN  128
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define IF_NAME_SIZE 128
#define LIBNET_INJECTION_TYPE   LIBNET_LINK_ADV

#define _support_IPv6_ 1
#ifndef VERSION
#define VERSION "1.4.0"
#endif

#ifdef _support_IPv6_
#define NDOP_SOLICATION 135
#define NDOP_ADVERTISE  136
typedef struct libnet_in6_addr in6_addr_t;

/* Pseudo header used for checksumming ICMP, TCP, UDP etc
 */
struct ipv6_pseudo_hdr {
	struct in6_addr source;
	struct in6_addr destination;
	u_int32_t ulp_length;
	u_int32_t  zero: 24,
		nexthdr:  8;
};
#endif

/* ipv6 related functions */
#ifdef _support_IPv6_
extern int ipv6_name_resolve(char* name, in6_addr_t* ip6addr);
extern libnet_ptag_t build_ndar(in6_addr_t spa, in6_addr_t tpa, int op, int optlen, u_char *opt, libnet_t *l);
extern int ipv6_find_mac(in6_addr_t addr, u_char* mac);
extern int find_neighbor_mac(libnet_t* l, in6_addr_t addr, u_char* mac);
extern int ndar_send(libnet_t *l, int op, u_char *sha, in6_addr_t spa, u_char *tha, in6_addr_t tpa);
#endif

#endif /* _ARPSPOOF_H_ */

/* EOF */
