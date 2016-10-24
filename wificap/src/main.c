/*
 * iwcap.c - A simply radiotap capture utility outputting pcap dumps
 *
 *    Copyright 2012 Jo-Philipp Wich <jow@openwrt.org>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <time.h>

#include "pcap.h"
#include "db.h"

#define ARPHRD_IEEE80211_RADIOTAP	803

#define DLT_IEEE802_11_RADIO		127
#define LEN_IEEE802_11_HDR			32

#define FRAMETYPE_MASK				0xFC
#define FRAMETYPE_BEACON			0x80
#define FRAMETYPE_DATA				0x08

#define FRAMETYPE_PROBEREQ      0x40

#define FRAMETYPE_ACK               0xD4
#define FRAMETYPE_PROBERESPONSE     0x50
#define FRAMETYPE_CTS               0xC4
#define FRAMETYPE_RTS               0xB4

#define FRAMETYPE_ASSOCREQ          0x00
#define FRAMETYPE_ASSOCRES          0x10
#define FRAMETYPE_AUTH              0xB0
#define FRAMETYPE_DEAUTH            0xC0

#define FRAMETYPE_QOS_DATA          0x88
#define FRAMETYPE_ACTION            0xD0
#define FRAMETYPE_NULL_FUNCTION     0x48


#if __BYTE_ORDER == __BIG_ENDIAN
#define le16(x) __bswap_16(x)
#else
#define le16(x) (x)
#endif

uint8_t run_dump   = 0;
uint8_t run_stop   = 0;
uint8_t run_daemon = 0;

uint32_t frames_captured = 0;
uint32_t frames_filtered = 0;

int capture_sock = -1;
const char *ifname = NULL;


struct ringbuf {
	uint32_t len;            /* number of slots */
	uint32_t fill;           /* last used slot */
	uint32_t slen;           /* slot size */
	void *buf;               /* ring memory */
};

struct ringbuf_entry {
	uint32_t len;            /* used slot memory */
	uint32_t olen;           /* original data size */
	uint32_t sec;            /* epoch of slot creation */
	uint32_t usec;			 /* epoch microseconds */
};

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ieee80211_radiotap_header {
	u_int8_t  it_version;    /* set to 0 */
	u_int8_t  it_pad;
	u_int16_t it_len;        /* entire length */
	u_int32_t it_present;    /* fields present */
} __attribute__((__packed__)) radiotap_hdr_t;

struct timeval tv;

int check_type(void) {

	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(capture_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	return (ifr.ifr_hwaddr.sa_family == ARPHRD_IEEE80211_RADIOTAP);
}

int set_promisc(int on) {

	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(capture_sock, SIOCGIFFLAGS, &ifr) < 0)
		return -1;

	if (on && !(ifr.ifr_flags & IFF_PROMISC)) {
		ifr.ifr_flags |= IFF_PROMISC;

		if (ioctl(capture_sock, SIOCSIFFLAGS, &ifr))
			return -1;

		return 1;
	}else if (!on && (ifr.ifr_flags & IFF_PROMISC)) {
		ifr.ifr_flags &= ~IFF_PROMISC;

		if (ioctl(capture_sock, SIOCSIFFLAGS, &ifr))
			return -1;

		return 1;
	}

	return 0;
}


void sig_dump(int sig) {                //signal
	run_dump = 1;
}

void sig_teardown(int sig) {
	run_stop = 1;
}

void write_pcap_header(FILE *o) {

	pcap_hdr_t ghdr = {
		.magic_number  = 0xa1b2c3d4,
		.version_major = 2,
		.version_minor = 4,
		.thiszone      = 0,
		.sigfigs       = 0,
		.snaplen       = 0xFFFF,
		.network       = DLT_IEEE802_11_RADIO
	};

	fwrite(&ghdr, 1, sizeof(ghdr), o);		//write to FILE* o
}

void write_pcap_frame(FILE *o, uint32_t *sec, uint32_t *usec, uint16_t len, uint16_t olen) {
	struct timeval tv;
	pcaprec_hdr_t fhdr;

	if (!sec || !usec) {
		gettimeofday(&tv, NULL);
	}else {
		tv.tv_sec  = *sec;
		tv.tv_usec = *usec;
	}

	fhdr.ts_sec   = tv.tv_sec;
	fhdr.ts_usec  = tv.tv_usec;
	fhdr.incl_len = len;
	fhdr.orig_len = olen;

	printf(	"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n",
		fhdr.ts_sec,fhdr.ts_usec);

	printf(	"ts.timestamp_s2:%u\n"
		"ts.timestamp_ms2:%u\n",
		tv.tv_sec,tv.tv_usec);
}

struct ringbuf * ringbuf_init(uint32_t num_item, uint16_t len_item) {
	static struct ringbuf r;

	if (len_item <= 0)
		return NULL;

	r.buf = malloc(num_item * (len_item + sizeof(struct ringbuf_entry)));

	if (r.buf) {
		r.len = num_item;
		r.fill = 0;
		r.slen = (len_item + sizeof(struct ringbuf_entry));

		memset(r.buf, 0, num_item * len_item);

		return &r;
	}

	return NULL;
}

struct ringbuf_entry * ringbuf_add(struct ringbuf *r) {

	struct timeval t;
	struct ringbuf_entry *e;

	gettimeofday(&t, NULL);

	e = r->buf + (r->fill++ * r->slen);
	r->fill %= r->len;

	memset(e, 0, r->slen);

	e->sec = t.tv_sec;
	e->usec = t.tv_usec;

	return e;
}

struct ringbuf_entry * ringbuf_get(struct ringbuf *r, int i) {

	struct ringbuf_entry *e = r->buf + (((r->fill + i) % r->len) * r->slen);

	if (e->len > 0)
		return e;

	return NULL;
}

void ringbuf_free(struct ringbuf *r) {

	free(r->buf);
	memset(r, 0, sizeof(*r));
}


void msg(const char *fmt, ...) {

	va_list ap;
	va_start(ap, fmt);

	if (run_daemon)
		vsyslog(LOG_INFO | LOG_USER, fmt, ap);
	else
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

struct tm * gettime(void) {

	char *wday[]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	struct tm *p;
	gettimeofday(&tv,NULL);
	p=localtime(&tv.tv_sec);
	printf("%d-%d-%d ", (1900+p->tm_year),(1+p->tm_mon),p->tm_mday); 
	printf("%s %d:%d:%d.%d\n\n",wday[p->tm_wday],p->tm_hour,p->tm_min,p->tm_sec,tv.tv_usec);
	return p;
}

int main(int argc, char **argv) 
{
	
	int i, n;
	int readsize;
	struct ringbuf *ring;
	struct ringbuf_entry *e;
	struct sockaddr_ll local = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL)
	};

	struct tm *ptime;

	pcaprec_hdr_t *ph;
	radiotap_hdr_t *rhdr;
	
	uint8_t frametype;
	uint8_t pktbuf[0xFFFF];
	ssize_t pktlen;

	FILE *o;

	int opt;
	const char* hostIp;	

	uint8_t promisc        = 0;
	uint8_t streaming      = 1;	//default changed
	uint8_t foreground     = 0;
	uint8_t probereq       = 1;
	uint8_t header_written = 0;

	uint32_t ringsz   = 1024 * 1024; 	// 1 Mbyte ring buffer 
	uint16_t pktcap   = 256;			 // truncate frames after 265KB 

	const char *output = NULL;

	while ((opt = getopt(argc, argv, "i:r:c:o:h:sf")) != -1) {

		switch (opt) {
		case 'i':
			ifname = optarg;
			if (!(local.sll_ifindex = if_nametoindex(ifname))) {
				msg("Unknown interface '%s'\n", ifname);
				return 2;
			}
			break;

		case 'c':
			pktcap = atoi(optarg);
			if (pktcap <= (sizeof(radiotap_hdr_t) + LEN_IEEE802_11_HDR)) {
				msg("Packet truncate after %d bytes is too short, "
					"must be at least %d bytes\n",
					pktcap, sizeof(radiotap_hdr_t) + LEN_IEEE802_11_HDR);
				return 4;
			}
			break;

		case 's':
			streaming = 1;
			break;

		case 'o':
			output = optarg;
			break;
		case 'h':
			hostIp = optarg;
			printf("hostIp is %s", hostIp);
			break;
		}
	}

	int ret;
	if((ret = db_init(hostIp))!=0) {
		printf("Init database failed!\n");
	}	

	if (!local.sll_ifindex) {
		msg("No interface specified\n");
		return 2;
	}

	if (!check_type()) {
		msg("Bad interface: not ARPHRD_IEEE80211_RADIOTAP\n");
		return 2;
	}
	
	if ((capture_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {	//create socket
		msg("Unable to create raw socket: %s\n",
				strerror(errno));
		return 6;
	}

	if (bind(capture_sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
		msg("Unable to bind to interface: %s\n",
			strerror(errno));
		return 7;
	}
	if(streaming) {
		msg("Monitoring interface %s ...\n", ifname);
	}

	//signal handler
	signal(SIGINT, sig_teardown);  
	signal(SIGTERM, sig_teardown);

	promisc = set_promisc(1);

	while (1) {			// capture loop 
		if (run_stop) {
			msg("Shutting down ...\n");

			if (promisc)
				set_promisc(0);

			if (ring)
				ringbuf_free(ring);

			return 0;
		}
	
		pktlen = recvfrom(capture_sock, pktbuf, sizeof(pktbuf), 0, NULL, 0);
		frames_captured++;

		/* check received frametype, if we should filter it, rewind the ring */
		rhdr = (radiotap_hdr_t *)pktbuf;
		ph = (pcaprec_hdr_t *)pktbuf;
		if (pktlen <= sizeof(radiotap_hdr_t) || le16(rhdr->it_len) >= pktlen) {
			frames_filtered++;
			continue;
		}

		frametype = *(uint8_t *)(pktbuf + le16(rhdr->it_len));

		frametype = frametype & FRAMETYPE_MASK;
		switch(frametype) {

			case FRAMETYPE_QOS_DATA:
				printf("\n========Qos Data========\n\n");
				ptime=gettime();	
				if(printPcapQos(pktbuf, pktlen, ptime, tv) != 0) {
					printf("Bad Frame For Qos, Continue\n");
				}
				break;	

			case FRAMETYPE_PROBEREQ:
				printf("\n========Prob Req==========\n");
				ptime=gettime();
				if(printPcapProbReq(pktbuf, pktlen, ptime, tv) != 0) {
					printf("printPcapProbReq falied\n");
				}
				break;

			case FRAMETYPE_NULL_FUNCTION:
				printf("\n======NULL Function=====\n");
				ptime=gettime();
				if(printPcapNull(pktbuf, pktlen, ptime, tv) != 0) {
					printf("printfPcapNull failed\n");	
				}
				break;
			case FRAMETYPE_BEACON:
				printf("\n======BEACON======\n");
				ptime=gettime();
				if(printPcapBeacon(pktbuf, pktlen, ptime, tv) != 0) {
					printf("printfPcapBeacon failed\n");
				}
				break;
			default: 
				break;
		}
   	 }	
	return 0;
}
