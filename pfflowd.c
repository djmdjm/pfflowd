/*
 * Copyright (c) 2003,2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: pfflowd.c,v 1.18 2004/09/06 12:25:57 djm Exp $ */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <pcap.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
#include <netdb.h>
#include "pfflowd.h"

static int verbose_flag = 0;            /* Debugging flag */
static struct timeval start_time;       /* "System boot" time, for SysUptime */
static int netflow_socket = -1;		/* Send socket */
static int direction = 0;		/* Filter for direction */
static u_int export_version = 5;	/* Currently v.1 and v.5 supported */
static u_int32_t flows_exported = 0;	/* Used for v.5 header */

/* 
 * Drop privileges and chroot, will exit on failure
 */
static void 
drop_privs(void)
{
	struct passwd *pw;
	
	if ((pw = getpwnam(PRIVDROP_USER)) == NULL) {
		syslog(LOG_ERR, "Unable to find unprivileged user \"%s\"", 
		    PRIVDROP_USER);
		exit(1);
	}
	if (chdir(PRIVDROP_CHROOT_DIR) != 0) {
		syslog(LOG_ERR, "Unable to chdir to chroot directory \"%s\": %s",
		    PRIVDROP_CHROOT_DIR, strerror(errno));
		exit(1);
	}
	if (chroot(PRIVDROP_CHROOT_DIR) != 0) {
		syslog(LOG_ERR, "Unable to chroot to directory \"%s\": %s",
		    PRIVDROP_CHROOT_DIR, strerror(errno));
		exit(1);
	}
	if (chdir("/") != 0) {
		syslog(LOG_ERR, "Unable to chdir to chroot root: %s",
		    strerror(errno));
		exit(1);
	}
	if (setgroups(1, &pw->pw_gid) != 0) {
		syslog(LOG_ERR, "Couldn't setgroups (%u): %s",
		    (unsigned int)pw->pw_gid, strerror(errno));
		exit(1);
	}
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		syslog(LOG_ERR, "Couldn't set gid (%u): %s",
		    (unsigned int)pw->pw_gid, strerror(errno));
		exit(1);
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		syslog(LOG_ERR, "Couldn't set uid (%u): %s",
		    (unsigned int)pw->pw_uid, strerror(errno));
		exit(1);
	}
}

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options] [bpf_program]\n", PROGNAME);
	fprintf(stderr, "  -i interface    Specify interface to listen on (default %s)\n", DEFAULT_INTERFACE);
	fprintf(stderr, "  -n host:port    Send NetFlow datagrams to host on port (mandatory)\n");
	fprintf(stderr, "  -r pcap_file    Specify packet capture file to read\n");
	fprintf(stderr, "  -S direction    Generation flows for \"in\" or \"out\" bound states (default any)\n");
	fprintf(stderr, "  -d              Don't daemonise\n");
	fprintf(stderr, "  -D              Debug mode: don't daemonise + verbosity\n");
	fprintf(stderr, "  -v              NetFlow export packet version (default %d)\n", export_version);
	fprintf(stderr, "  -h              Display this help\n");
	fprintf(stderr, "\n");
}

/* Signal handlers */
static void sighand_exit(int signum)
{
	struct syslog_data sd = SYSLOG_DATA_INIT;

	syslog_r(LOG_INFO, &sd, "%s exiting on signal %d", PROGNAME, signum);

	_exit(0);
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
 * Parse host:port into sockaddr. Will exit on failure
 */
static void
parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
	char *orig, *host, *port;
	struct addrinfo hints, *res;
	int herr;

	if ((host = orig = strdup(s)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	if ((port = strrchr(host, ':')) == NULL ||
	    *(++port) == '\0' || *host == '\0') {
		fprintf(stderr, "Invalid -n argument.\n");
		usage();
		exit(1);
	}
	*(port - 1) = '\0';
	
	/* Accept [host]:port for numeric IPv6 addresses */
	if (*host == '[' && *(port - 2) == ']') {
		host++;
		*(port - 2) = '\0';
	}

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	if ((herr = getaddrinfo(host, port, &hints, &res)) == -1) {
		fprintf(stderr, "Address lookup failed: %s\n",
		    gai_strerror(herr));
		exit(1);
	}
	if (res == NULL || res->ai_addr == NULL) {
		fprintf(stderr, "No addresses found for %s:%s\n", host, port);
		exit(1);
	}
	if (res->ai_addrlen > *len) {
		fprintf(stderr, "Address too long\n");
		exit(1);
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	free(orig);
	*len = res->ai_addrlen;
}

/*
 * Return a connected socket to the specified address
 */
static int
connsock(struct sockaddr *addr, socklen_t len)
{
	int s;

	if ((s = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "socket() error: %s\n", 
		    strerror(errno));
		exit(1);
	}
	if (connect(s, addr, len) == -1) {
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

static int
send_netflow_v1(const struct _PFSYNC_STATE *st, u_int n, int *flows_exp)
{
	char now_s[64];
	int i, j, offset, num_packets, err;
	socklen_t errsz;
	struct NF1_FLOW *flw = NULL;
	struct NF1_HEADER *hdr = NULL;
	struct timeval now_tv;
	struct tm now_tm;
	time_t now;
	u_int32_t uptime_ms;
	u_int8_t packet[NF1_MAXPACKET_SIZE];

	if (verbose_flag) {
		now = time(NULL);
		localtime_r(&now, &now_tm);
		strftime(now_s, sizeof(now_s), "%Y-%m-%dT%H:%M:%S", &now_tm);
	}

	gettimeofday(&now_tv, NULL);
	uptime_ms = timeval_sub_ms(&now_tv, &start_time);

	hdr = (struct NF1_HEADER *)packet;
	for(num_packets = offset = j = i = 0; i < n; i++) {
		struct pf_state_host src, dst;
		u_int32_t bytes_in, bytes_out;
		u_int32_t packets_in, packets_out;
		char src_s[64], dst_s[64], rt_s[64], pbuf[16], creation_s[64];
		time_t creation_tt;
		u_int32_t creation;
		struct tm creation_tm;

		if (netflow_socket != -1 && j >= NF1_MAXFLOWS - 1) {
			if (verbose_flag) {
				syslog(LOG_DEBUG,
				    "Sending flow packet len = %d", offset);
			}
			hdr->flows = htons(hdr->flows);
			errsz = sizeof(err);
			getsockopt(netflow_socket, SOL_SOCKET, SO_ERROR,
			    &err, &errsz); /* Clear ICMP errors */
			if (send(netflow_socket, packet,
			    (size_t)offset, 0) == -1) {
				syslog(LOG_DEBUG, "send: %s", strerror(errno));
				return -1;
			}
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

		if (st[i].af != AF_INET)
			continue;
		if (direction != 0 && st[i].direction != direction)
			continue;

		/* Copy/convert only what we can eat */
		creation = ntohl(st[i].creation) * 1000;
		if (creation > uptime_ms)
			creation = uptime_ms; /* Avoid u_int wrap */

		if (st[i].direction == PF_OUT) {
			memcpy(&src, &st[i].lan, sizeof(src));
			memcpy(&dst, &st[i].ext, sizeof(dst));
		} else {
			memcpy(&src, &st[i].ext, sizeof(src));
			memcpy(&dst, &st[i].lan, sizeof(dst));
		}

		flw = (struct NF1_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st[i].packets[0] != 0) {
			flw->src_ip = src.addr.v4.s_addr;
			flw->dest_ip = dst.addr.v4.s_addr;
			flw->src_port = src.port;
			flw->dest_port = dst.port;
			flw->flow_packets = st[i].packets[0];
			flw->flow_octets = st[i].bytes[0];
			flw->flow_start = htonl(uptime_ms - creation);
			flw->flow_finish = htonl(uptime_ms);
			flw->protocol = st[i].proto;
			flw->tcp_flags = 0;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st[i].packets[1] != 0) {
			flw->src_ip = dst.addr.v4.s_addr;
			flw->dest_ip = src.addr.v4.s_addr;
			flw->src_port = dst.port;
			flw->dest_port = src.port;
			flw->flow_packets = st[i].packets[1];
			flw->flow_octets = st[i].bytes[1];
			flw->flow_start = htonl(uptime_ms - creation);
			flw->flow_finish = htonl(uptime_ms);
			flw->protocol = st[i].proto;
			flw->tcp_flags = 0;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF1_FLOW *)(packet + offset);

		if (verbose_flag) {
			packets_out = ntohl(st[i].packets[0]);
			packets_in = ntohl(st[i].packets[1]);
			bytes_out = ntohl(st[i].bytes[0]);
			bytes_in = ntohl(st[i].bytes[1]);

			creation_tt = now - (creation / 1000);
			localtime_r(&creation_tt, &creation_tm);
			strftime(creation_s, sizeof(creation_s), 
			    "%Y-%m-%dT%H:%M:%S", &creation_tm);

			format_pf_host(src_s, sizeof(src_s), &src, st[i].af);
			format_pf_host(dst_s, sizeof(dst_s), &dst, st[i].af);
			inet_ntop(st[i].af, &st[i].rt_addr, rt_s, sizeof(rt_s));

			if (st[i].proto == IPPROTO_TCP || 
			    st[i].proto == IPPROTO_UDP) {
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(src.port));
				strlcat(src_s, pbuf, sizeof(src_s));
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(dst.port));
				strlcat(dst_s, pbuf, sizeof(dst_s));
			}

			syslog(LOG_DEBUG, "IFACE %s", st[i].ifname); 
			syslog(LOG_DEBUG, "GWY %s", rt_s); 
			syslog(LOG_DEBUG, "FLOW proto %d direction %d", 
			    st[i].proto, st[i].direction);
			syslog(LOG_DEBUG, "\tstart %s(%u) finish %s(%u)",
			    creation_s, uptime_ms - creation, 
			    now_s, uptime_ms);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    src_s, dst_s, bytes_out, packets_out);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    dst_s, src_s, bytes_in, packets_in);
		}
	}
	/* Send any leftovers */
	if (netflow_socket != -1 && j != 0) {
		if (verbose_flag) {
			syslog(LOG_DEBUG, "Sending flow packet len = %d",
			    offset);
		}
		hdr->flows = htons(hdr->flows);
		errsz = sizeof(err);
		getsockopt(netflow_socket, SOL_SOCKET, SO_ERROR,
		    &err, &errsz); /* Clear ICMP errors */
		if (send(netflow_socket, packet, (size_t)offset, 0) == -1) {
			syslog(LOG_DEBUG, "send: %s", strerror(errno));
			return -1;
		}
		num_packets++;
	}

	return (ntohs(hdr->flows));
}

static int
send_netflow_v5(const struct _PFSYNC_STATE *st, u_int n, int *flows_exp)
{
	char now_s[64];
	int i, j, offset, num_packets, err;
	socklen_t errsz;
	struct NF5_FLOW *flw = NULL;
	struct NF5_HEADER *hdr = NULL;
	struct timeval now_tv;
	struct tm now_tm;
	time_t now;
	u_int32_t uptime_ms;
	u_int8_t packet[NF5_MAXPACKET_SIZE];

	if (verbose_flag) {
		now = time(NULL);
		localtime_r(&now, &now_tm);
		strftime(now_s, sizeof(now_s), "%Y-%m-%dT%H:%M:%S", &now_tm);
	}

	gettimeofday(&now_tv, NULL);
	uptime_ms = timeval_sub_ms(&now_tv, &start_time);

	hdr = (struct NF5_HEADER *)packet;
	for(num_packets = offset = j = i = 0; i < n; i++) {
		struct pf_state_host src, dst;
		u_int32_t bytes_in, bytes_out, packets_in, packets_out;
		u_int32_t creation;
		char src_s[64], dst_s[64], rt_s[64], pbuf[16], creation_s[64];
		time_t creation_tt;
		struct tm creation_tm;

		if (netflow_socket != -1 && j >= NF5_MAXFLOWS - 1) {
			if (verbose_flag) {
				syslog(LOG_DEBUG,
				    "Sending flow packet len = %d", offset);
			}
			hdr->flows = htons(hdr->flows);
			errsz = sizeof(err);
			getsockopt(netflow_socket, SOL_SOCKET, SO_ERROR,
			    &err, &errsz); /* Clear ICMP errors */
			if (send(netflow_socket, packet,
			    (size_t)offset, 0) == -1) {
				syslog(LOG_DEBUG, "send: %s", strerror(errno));
				return -1;
			}
			j = 0;
			num_packets++;
		}

		if (netflow_socket != -1 && j == 0) {
			memset(&packet, '\0', sizeof(packet));
			hdr->version = htons(5);
			hdr->flows = 0; /* Filled in as we go */
			hdr->uptime_ms = htonl(uptime_ms);
			hdr->time_sec = htonl(now_tv.tv_sec);
			hdr->time_nanosec = htonl(now_tv.tv_usec * 1000);
			hdr->flow_sequence = htonl(*flows_exp);
			/* Other fields are left zero */
			offset = sizeof(*hdr);
		}

		if (st[i].af != AF_INET)
			continue;
		if (direction != 0 && st[i].direction != direction)
			continue;

		/* Copy/convert only what we can eat */
		creation = ntohl(st[i].creation) * 1000;
		if (creation > uptime_ms)
			creation = uptime_ms; /* Avoid u_int wrap */

		if (st[i].direction == PF_OUT) {
			memcpy(&src, &st[i].lan, sizeof(src));
			memcpy(&dst, &st[i].ext, sizeof(dst));
		} else {
			memcpy(&src, &st[i].ext, sizeof(src));
			memcpy(&dst, &st[i].lan, sizeof(dst));
		}

		flw = (struct NF5_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st[i].packets[0] != 0) {
			flw->src_ip = src.addr.v4.s_addr;
			flw->dest_ip = dst.addr.v4.s_addr;
			flw->src_port = src.port;
			flw->dest_port = dst.port;
			flw->flow_packets = st[i].packets[0];
			flw->flow_octets = st[i].bytes[0];
			flw->flow_start = htonl(uptime_ms - creation);
			flw->flow_finish = htonl(uptime_ms);
			flw->tcp_flags = 0;
			flw->protocol = st[i].proto;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF5_FLOW *)(packet + offset);
		if (netflow_socket != -1 && st[i].packets[1] != 0) {
			flw->src_ip = dst.addr.v4.s_addr;
			flw->dest_ip = src.addr.v4.s_addr;
			flw->src_port = dst.port;
			flw->dest_port = src.port;
			flw->flow_packets = st[i].packets[1];
			flw->flow_octets = st[i].bytes[1];
			flw->flow_start = htonl(uptime_ms - creation);
			flw->flow_finish = htonl(uptime_ms);
			flw->tcp_flags = 0;
			flw->protocol = st[i].proto;
			offset += sizeof(*flw);
			j++;
			hdr->flows++;
		}
		flw = (struct NF5_FLOW *)(packet + offset);

		if (verbose_flag) {
			packets_out = ntohl(st[i].packets[0]);
			packets_in = ntohl(st[i].packets[1]);
			bytes_out = ntohl(st[i].bytes[0]);
			bytes_in = ntohl(st[i].bytes[1]);

			creation_tt = now - (creation / 1000);
			localtime_r(&creation_tt, &creation_tm);
			strftime(creation_s, sizeof(creation_s), 
			    "%Y-%m-%dT%H:%M:%S", &creation_tm);

			format_pf_host(src_s, sizeof(src_s), &src, st[i].af);
			format_pf_host(dst_s, sizeof(dst_s), &dst, st[i].af);
			inet_ntop(st[i].af, &st[i].rt_addr, rt_s, sizeof(rt_s));

			if (st[i].proto == IPPROTO_TCP || 
			    st[i].proto == IPPROTO_UDP) {
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(src.port));
				strlcat(src_s, pbuf, sizeof(src_s));
				snprintf(pbuf, sizeof(pbuf), ":%d", 
				    ntohs(dst.port));
				strlcat(dst_s, pbuf, sizeof(dst_s));
			}

			syslog(LOG_DEBUG, "IFACE %s", st[i].ifname); 
			syslog(LOG_DEBUG, "GWY %s", rt_s); 
			syslog(LOG_DEBUG, "FLOW proto %d direction %d", 
			    st[i].proto, st[i].direction);
			syslog(LOG_DEBUG, "\tstart %s(%u) finish %s(%u)",
			    creation_s, uptime_ms - creation, 
			    now_s, uptime_ms);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    src_s, dst_s, bytes_out, packets_out);
			syslog(LOG_DEBUG, "\t%s -> %s %d bytes %d packets",
			    dst_s, src_s, bytes_in, packets_in);
		}
	}
	/* Send any leftovers */
	if (netflow_socket != -1 && j != 0) {
		if (verbose_flag) {
			syslog(LOG_DEBUG, "Sending flow packet len = %d",
			    offset);
		}
		hdr->flows = htons(hdr->flows);
		errsz = sizeof(err);
		getsockopt(netflow_socket, SOL_SOCKET, SO_ERROR,
		    &err, &errsz); /* Clear ICMP errors */
		if (send(netflow_socket, packet, (size_t)offset, 0) == -1) {
			syslog(LOG_DEBUG, "send: %s", strerror(errno));
			return -1;
		}
		num_packets++;
	}

	return (ntohs(hdr->flows));
}

/*
 * Per-packet callback function from libpcap. 
 */
static void
packet_cb(u_char *user_data, const struct pcap_pkthdr* phdr, 
    const u_char *pkt)
{
	const struct pfsync_header *ph = (const struct pfsync_header *)pkt;
	const struct _PFSYNC_STATE *st;
	int r = 0;

	if (phdr->caplen < PFSYNC_HDRLEN) {
		syslog(LOG_WARNING, "Runt pfsync packet header");
		return;
	}
	if (ph->version != _PFSYNC_VER) {
		syslog(LOG_WARNING, "Unsupported pfsync version %d, exiting",
		    ph->version);
		exit(1);
	}
	if (ph->count == 0) {
		syslog(LOG_WARNING, "Empty pfsync packet");
		return;
	}
	/* Skip non-delete messages */
	if (ph->action != PFSYNC_ACT_DEL)
		return;
	if (sizeof(*ph) + (sizeof(*st) * ph->count) > phdr->caplen) {
		syslog(LOG_WARNING, "Runt pfsync packet");
		return;
	}

	st = (const struct _PFSYNC_STATE *)((const u_int8_t *)ph + sizeof(*ph));

	switch (export_version) {
	case 1:
		r = send_netflow_v1(st, ph->count, &flows_exported);
		break;
	case 5:
		r = send_netflow_v5(st, ph->count, &flows_exported);
		break;
	default:
		/* should never reach this point */
		syslog(LOG_DEBUG, "Invalid netflow version, exiting");
		exit(1);
	}

	if (r > 0) {
		flows_exported += r;
		if (verbose_flag)
			syslog(LOG_DEBUG, "flows_exported = %d", flows_exported);
	}
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
#ifdef BIOCLOCK
	/*
	 * If we are reading from an device (not a file), then 
	 * lock the underlying BPF device to prevent changes in the 
	 * unprivileged child
	 */
	if (dev != NULL && ioctl(pcap_fileno(*pcap), BIOCLOCK) < 0) {
		fprintf(stderr, "ioctl(BIOCLOCK) failed: %s\n",
		    strerror(errno));
		exit(1);
	}
#endif
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
	struct sockaddr_storage dest;
	socklen_t destlen;

	bpf_prog = NULL;
	dev = capfile = NULL;
	dontfork_flag = 0;
	memset(&dest, '\0', sizeof(dest));
	destlen = 0;
	while ((ch = getopt(argc, argv, "hdDi:n:r:S:v:")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			return (0);
		case 'S':
			if (strcasecmp(optarg, "any") == 0) {
				direction = 0;
				break;
			}
			if (strcasecmp(optarg, "in") == 0) {
				direction = PF_IN;
				break;
			}
			if (strcasecmp(optarg, "out") == 0) {
				direction = PF_OUT;
				break;
			}
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
			destlen = sizeof(dest);
			parse_hostport(optarg, (struct sockaddr *)&dest,
			    &destlen);
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
		case 'v':
			switch((export_version = atoi(optarg))) {
			case 1:
			case 5:
				break;
			default:
				fprintf(stderr, "Invalid NetFlow version\n");
				exit(1);
			}
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
	if (dest.ss_family != 0)
		netflow_socket = connsock((struct sockaddr *)&dest, destlen);
	else {
		fprintf(stderr, "No export target defined\n");
		if (!verbose_flag)
			exit(1);
	}

fprintf(stderr, "ZZZZ %d\n", netflow_socket);

	if (dontfork_flag) {
		if (!verbose_flag)
			drop_privs();
		openlog(__progname, LOG_PID|LOG_PERROR, LOG_DAEMON);
	} else {	
		daemon(0, 0);
		openlog(__progname, LOG_PID, LOG_DAEMON);

		if (pidfile(NULL) == -1) {
			syslog(LOG_WARNING, "Couldn't write pidfile: %s", 
			    strerror(errno));
		}

		/* Close and reopen syslog to pickup chrooted /dev/log */
		closelog();
		openlog(__progname, LOG_PID, LOG_DAEMON);

		drop_privs();

		signal(SIGINT, sighand_exit);
		signal(SIGTERM, sighand_exit);
	}

	if (dev != NULL)
		syslog(LOG_NOTICE, "%s listening on %s", __progname, dev);

	/* Main processing loop */
	gettimeofday(&start_time, NULL);

	r = pcap_loop(pcap, -1, packet_cb, NULL);
	if (r == -1) {
		syslog(LOG_ERR, "pcap_dispatch: %s", pcap_geterr(pcap));
		exit(1);
	}

	if (r == 0 && capfile == NULL)
		syslog(LOG_NOTICE, "Exiting on pcap EOF");

	exit(0);
}
