/*
 * Copyright 2003 Damien Miller <djm@mindrot.org> All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: pfflowd.c,v 1.1.1.1 2003/06/22 03:42:25 djm Exp $ */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <util.h>

#define DEFAULT_INTERFACE	"pfsync0"
#define LIBPCAP_SNAPLEN		2020	/* Default MTU */

static int verbose_flag = 0;		/* Debugging flag */
static int exit_flag = 0;		/* Signal handler flags */
static struct timeval start_time;	/* "System boot" time, for SysUptime */
static int netflow_socket = -1;

/*
 * This is the Cisco Netflow(tm) version 1 packet format
 * Based on:
 * http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm
 */
struct NF1_HEADER {
	u_int16_t version, flows;
	u_int32_t uptime_ms, time_sec, time_nanosec;
};
struct NF1_FLOW {
	u_int32_t src_ip, dest_ip, nexthop_ip;
	u_int16_t if_index_in, if_index_out;
	u_int32_t flow_packets, flow_octets;
	u_int32_t flow_start, flow_finish;
	u_int16_t src_port, dest_port;
	u_int16_t pad1;
	u_int8_t protocol, tos, tcp_flags;
	u_int8_t pad2, pad3, pad4;
	u_int32_t reserved1;
#if 0
 	u_int8_t reserved2; /* XXX: no longer used */
#endif
};
/* Maximum of 24 flows per packet */
#define NF1_MAXFLOWS		24
#define NF1_MAXPACKET_SIZE	(sizeof(struct NF1_HEADER) + \
				 (NF1_MAXFLOWS * sizeof(struct NF1_FLOW)))

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: pfsyncdump [options] [bpf_program]\n");
	fprintf(stderr, "  -i interface    Specify interface to listen on (default %s)\n", DEFAULT_INTERFACE);
	fprintf(stderr, "  -r pcap_file    Specify packet capture file to read\n");
	fprintf(stderr, "  -d              Don't daemonise\n");
	fprintf(stderr, "  -D              Debug mode: don't daemonise + verbosity\n");
	fprintf(stderr, "  -h              Display this help\n");
	fprintf(stderr, "\n");
}

/* Signal handlers */
static void sighand_exit(int signum)
{
	exit_flag = signum;
}

/*
 * Subtract two timevals. Returns (t1 - t2) in milliseconds.
 */
static u_int32_t
timeval_sub_ms(struct timeval *t1, struct timeval *t2)
{
	struct timeval res;

	res.tv_sec = t1->tv_sec - t2->tv_sec;
	res.tv_usec = t1->tv_usec - t2->tv_usec;
	if (res.tv_usec < 0) {
		res.tv_usec += 1000000L;
		res.tv_sec--;
	}
	return ((u_int32_t)res.tv_sec * 1000 + (u_int32_t)res.tv_usec / 1000);
}

/*
 * Parse IPv4 host:port into sockaddr. Will exit on failure
 */
static void
parse_hostport(const char *s, struct sockaddr_in *addr)
{
	char *host, *port;

	if ((host = strdup(s)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	if ((port = strchr(host, ':')) == NULL || *(++port) == '\0') {
		fprintf(stderr, "Invalid -n option.\n");
		usage();
		exit(1);
	}
	*(port - 1) = '\0';
	addr->sin_family = AF_INET;
	addr->sin_port = atoi(port);
	if (addr->sin_port <= 0 || addr->sin_port >= 65536) {
		fprintf(stderr, "Invalid -n port.\n");
		usage();
		exit(1);
	}
	addr->sin_port = htons(addr->sin_port);
	if (inet_aton(host, &addr->sin_addr) == 0) {
		fprintf(stderr, "Invalid -n host.\n");
		usage();
		exit(1);
	}
	free(host);
}

/*
 * Return a connected PF_INET socket to the specified address
 */
static int
connnected_socket(struct sockaddr_in *addr)
{
	int s;

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket() error: %s\n", 
		    strerror(errno));
		exit(1);
	}
	if (connect(s, (struct sockaddr*)addr, sizeof(*addr)) == -1) {
		fprintf(stderr, "connect() error: %s\n",
		    strerror(errno));
		exit(1);
	}

	return(s);
}

static void 
format_pf_host(char *buf, size_t n, struct pf_state_host *h, sa_family_t af)
{
	const char *err = NULL;

	switch (af) {
	case AF_INET:
	case AF_INET6:
		if (inet_ntop(af, &h->addr, buf, n) == NULL)
			err = strerror(errno);
		break;
	default:
		err = "Unsupported address family";
		break;
	}
	if (err != NULL)
		strlcpy(buf, err, n);
}

/*
 * Per-packet callback function from libpcap. 
 */
static void
packet_cb(u_char *user_data, const struct pcap_pkthdr* phdr, 
    const u_char *pkt)
{
	const struct pfsync_header *ph;
	int i;
	size_t off;
	time_t now;
	struct tm now_tm;
	struct timeval now_tv;
	char now_s[64];
	u_int32_t uptime_ms;
	u_int8_t packet[NF1_MAXPACKET_SIZE];	/* Maximum allowed packet size (24 flows) */
	struct NF1_HEADER *hdr = NULL;
	struct NF1_FLOW *flw = NULL;
	int j, offset, num_packets;

	if (phdr->caplen < PFSYNC_HDRLEN) {
		syslog(LOG_WARNING, "Runt pfsync packet header");
		return;
	}

	ph = (const struct pfsync_header*)pkt;

	if (ph->version != 1) {
		syslog(LOG_WARNING, "Unsupported pfsync version %d, skipping",
		    ph->version);
		/* XXX - exit */
		return;
	}

	if (ph->action != PFSYNC_ACT_DEL)
		return;

	if (verbose_flag) {
		now = time(NULL);
		localtime_r(&now, &now_tm);
		strftime(now_s, sizeof(now_s), "%Y-%m-%dT%H:%M:%S", &now_tm);
	}

	gettimeofday(&now_tv, NULL);
	uptime_ms = timeval_sub_ms(&now_tv, &start_time);

	hdr = (struct NF1_HEADER *)packet;
	for(num_packets = offset = j = i = 0; i < ph->count; i++) {
		const struct pf_state *st;
		struct pf_state_host src, dst;
		u_int32_t bytes_in, bytes_out;
		u_int32_t packets_in, packets_out;
		char src_s[64], dst_s[64], pbuf[16], creation_s[64];
		time_t creation;
		struct tm creation_tm;
		struct timeval creation_tv;

		off = sizeof(*ph) + (sizeof(*st) * i);
		if (off + sizeof(*st) > phdr->caplen) {
			syslog(LOG_WARNING, "Runt pfsync packet");
			return;
		}

		if (netflow_socket != -1 && j >= NF1_MAXFLOWS - 1) {
			if (verbose_flag)
				syslog(LOG_DEBUG, "Sending flow packet len = %d", offset);
			hdr->flows = htons(hdr->flows);
			if (send(netflow_socket, packet, (size_t)offset, 0) == -1)
				return;
			j = 0;
			num_packets++;
		}
		
		if (netflow_socket != -1 && j == 0) {
			memset(&packet, '\0', sizeof(packet));
			hdr->version = htons(1);
			hdr->flows = 0; /* Filled in as we go */
			hdr->uptime_ms = htonl(uptime_ms);
			hdr->time_sec = htonl(now_tv.tv_sec);
			hdr->time_nanosec = htonl(now_tv.tv_usec * 1000);
			offset = sizeof(*hdr);
		}

		st = (const struct pf_state *)(pkt + off);
		if (st->af != AF_INET)
			continue; /* XXX IPv6 support */

		/* Copy/convert only what we can eat */
		creation = now - ntohl(st->creation);
		creation_tv.tv_sec = creation;
		creation_tv.tv_usec = 0;

		if (st->direction == PF_OUT) {
			memcpy(&src, &st->lan, sizeof(src));
			memcpy(&dst, &st->ext, sizeof(dst));
		} else {
			memcpy(&src, &st->ext, sizeof(src));
			memcpy(&dst, &st->lan, sizeof(dst));
		}

		/* XXX - IPv4 only for now */
		flw = (struct NF1_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st->packets[0] != 0) {
			flw->src_ip = src.addr.v4.s_addr;
			flw->dest_ip = dst.addr.v4.s_addr;
			flw->src_port = src.port;
			flw->dest_port = dst.port;
			flw->flow_packets = st->packets[0];
			flw->flow_octets = st->bytes[0];
			flw->flow_start = htonl(timeval_sub_ms(&creation_tv, &start_time));
			flw->flow_finish = htonl(timeval_sub_ms(&now_tv, &start_time));
			flw->protocol = st->proto;
			flw->tcp_flags = 0;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st->packets[1] != 0) {
			flw->src_ip = dst.addr.v4.s_addr;
			flw->dest_ip = src.addr.v4.s_addr;
			flw->src_port = dst.port;
			flw->dest_port = src.port;
			flw->flow_packets = st->packets[1];
			flw->flow_octets = st->bytes[1];
			flw->flow_start = htonl(timeval_sub_ms(&creation_tv, &start_time));
			flw->flow_finish = htonl(timeval_sub_ms(&now_tv, &start_time));
			flw->protocol = st->proto;
			flw->tcp_flags = 0;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);

		if (verbose_flag) {
			packets_out = ntohl(st->packets[0]);
			packets_in = ntohl(st->packets[1]);
			bytes_out = ntohl(st->bytes[0]);
			bytes_in = ntohl(st->bytes[1]);

			localtime_r(&creation, &creation_tm);
			strftime(creation_s, sizeof(creation_s), 
			    "%Y-%m-%dT%H:%M:%S", &creation_tm);

			format_pf_host(src_s, sizeof(src_s), &src, st->af);
			format_pf_host(dst_s, sizeof(dst_s), &dst, st->af);

			if (st->proto == IPPROTO_TCP || 
			    st->proto == IPPROTO_UDP) {
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(src.port));
				strlcat(src_s, pbuf, sizeof(src_s));
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(dst.port));
				strlcat(dst_s, pbuf, sizeof(dst_s));
			}

			syslog(LOG_DEBUG, "FLOW proto %d direction %d", 
			    st->proto, st->direction);
			syslog(LOG_DEBUG, "\tstart %s finish %s",
			    creation_s, now_s);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    src_s, dst_s, bytes_out, packets_out);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    dst_s, src_s, bytes_in, packets_in);
		}
	}
	/* Send any leftovers */
	if (netflow_socket != -1 && j != 0) {
		if (verbose_flag)
			syslog(LOG_DEBUG, "Sending flow packet len = %d", offset);
		hdr->flows = htons(hdr->flows);
		if (send(netflow_socket, packet, (size_t)offset, 0) == -1)
			return;
		num_packets++;
	}

/*	return (num_packets); */
}

/*
 * Open either interface specified by "dev" or pcap file specified by 
 * "capfile". Optionally apply filter "bpf_prog"
 */
static void
setup_packet_capture(struct pcap **pcap, char *dev, 
    char *capfile, char *bpf_prog)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	struct bpf_program prog_c;

	/* Open pcap */
	if (dev != NULL) {
		if ((*pcap = pcap_open_live(dev, LIBPCAP_SNAPLEN, 
		    1, 0, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_live: %s\n", ebuf);
			exit(1);
		}
	} else {
		if ((*pcap = pcap_open_offline(capfile, ebuf)) == NULL) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n", 
			    capfile, ebuf);
			exit(1);
		}
	}
	/* XXX - check datalink */
	/* Attach BPF filter, if specified */
	if (bpf_prog != NULL) {
		if (pcap_compile(*pcap, &prog_c, bpf_prog, 1, 0) == -1) {
			fprintf(stderr, "pcap_compile(\"%s\"): %s\n", 
			    bpf_prog, pcap_geterr(*pcap));
			exit(1);
		}
		if (pcap_setfilter(*pcap, &prog_c) == -1) {
			fprintf(stderr, "pcap_setfilter: %s\n", 
			    pcap_geterr(*pcap));
			exit(1);
		}
	}
}

static char *
argv_join(int argc, char **argv)
{
	int i;
	size_t ret_len;
	char *ret;

	ret_len = 0;
	ret = NULL;
	for (i = 0; i < argc; i++) {
		ret_len += strlen(argv[i]);
		if (i != 0)
			ret_len++; /* Make room for ' ' */
		if ((ret = realloc(ret, ret_len + 1)) == NULL) {
			fprintf(stderr, "Memory allocation failed.\n");
			exit(1);
		}
		if (i == 0)
			ret[0] = '\0';
		else
			strlcat(ret, " ", ret_len + 1);
			
		strlcat(ret, argv[i], ret_len + 1);
	}

	return (ret);
}

int
main(int argc, char **argv)
{
	char *dev, *capfile, *bpf_prog;
	extern char *optarg;
	extern int optind;
	extern char *__progname;
	int ch, dontfork_flag, r;
	pcap_t *pcap = NULL;
	struct sockaddr_in netflow_dest;
	
	bpf_prog = NULL;
	dev = capfile = NULL;
	dontfork_flag = 0;
	memset(&netflow_dest, '\0', sizeof(netflow_dest));
	while ((ch = getopt(argc, argv, "hdDi:n:r:")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			return (0);
		case 'D':
			verbose_flag = 1;
			/* FALLTHROUGH */
		case 'd':
			dontfork_flag = 1;
			break;
		case 'i':
			if (capfile != NULL || dev != NULL) {
				fprintf(stderr, "Packet source already specified.\n\n");
				usage();
				exit(1);
			}
			dev = optarg;
			break;
		case 'n':
			/* Will exit on failure */
			parse_hostport(optarg, &netflow_dest);
			break;
		case 'r':
			if (capfile != NULL || dev != NULL) {
				fprintf(stderr, "Packet source already specified.\n\n");
				usage();
				exit(1);
			}
			capfile = optarg;
			dontfork_flag = 1;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (capfile == NULL && dev == NULL)
		dev = DEFAULT_INTERFACE;

	/* join remaining arguments (if any) into bpf program */
	bpf_prog = argv_join(argc - optind, argv + optind);

	/* Will exit on failure */
	setup_packet_capture(&pcap, dev, capfile, bpf_prog);
	
	/* Netflow send socket */
	if (netflow_dest.sin_family != 0)
		netflow_socket = connnected_socket(&netflow_dest);

	if (dontfork_flag) {
		openlog(__progname, LOG_PID|LOG_PERROR, LOG_DAEMON);
	} else {	
		daemon(0, 0);
		openlog(__progname, LOG_PID, LOG_DAEMON);

		if (pidfile(NULL) == -1) {
			syslog(LOG_WARNING, "Couldn't write pidfile: %s", 
			    strerror(errno));
		}

		signal(SIGINT, sighand_exit);
		signal(SIGTERM, sighand_exit);
	}

	if (dev != NULL)
		syslog(LOG_NOTICE, "%s listening on %s", __progname, dev);

	/* Main processing loop */
	gettimeofday(&start_time, NULL);
	for(;;) {
		struct pollfd pl[1];

		if (exit_flag) {
			syslog(LOG_NOTICE, "Exiting on signal %d", exit_flag);
			exit(0);
		}

		/*
		 * Silly libpcap's timeout function doesn't work, so we
		 * do it here (only if we are reading live)
		 */
		r = 0;
		if (capfile == NULL) {
			memset(pl, '\0', sizeof(pl));
			pl[0].events = POLLIN|POLLERR|POLLHUP;
			pl[0].fd = pcap_fileno(pcap);
			if (poll(pl, 1, -1) == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "poll: %s", strerror(errno));
				exit(1);
			}
			/* Shouldn't happen unless we specify a timeout */
			if (pl[0].revents == 0)
				continue;
		}

		r = pcap_dispatch(pcap, 1024, packet_cb, NULL);
		if (r == -1) {
			syslog(LOG_ERR, "pcap_dispatch: %s", pcap_geterr(pcap));
			exit(1);
		} else if (r == 0) {
			syslog(LOG_NOTICE, "Exiting on pcap EOF");
			exit(0);
		}
	}

	/* NOTREACHED */
	exit(1);
}
