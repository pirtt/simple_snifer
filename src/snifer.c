# include <pcap.h>
# include <stdio.h>
# include <stdlib.h>
# include <ctype.h>
# include <string.h>
# include <linux/if_ether.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define LEN 16

typedef	u_int32_t tcp_seq;

struct eth_header 
{
	u_int8_t ether_dhost[ETH_ALEN];
	u_int8_t ether_shost[ETH_ALEN];
	u_int16_t ether_lenth;
} __attribute__ ((__packed__));

struct ip_header
{
# if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
# elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
# else
# error "Please fix <bits/endian.h>"
# endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
} __attribute__ ((__packed__));

struct udp_header
{
  __extension__ union
  {
    struct
    {
      u_int16_t uh_sport;		/* source port */
      u_int16_t uh_dport;		/* destination port */
      u_int16_t uh_ulen;		/* udp length */
      u_int16_t uh_sum;		    /* udp checksum */
    } __attribute__ ((__packed__));
    struct
    {
      u_int16_t source;
      u_int16_t dest;
      u_int16_t len;
      u_int16_t check;
    } __attribute__ ((__packed__));
  };
} __attribute__ ((__packed__));

struct tcp_header
{
	__extension__ union
    {
    	struct
    	{
			u_int16_t th_sport;		/* source port */
			u_int16_t th_dport;		/* destination port */
			tcp_seq th_seq;			/* sequence number */
			tcp_seq th_ack;			/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int8_t th_x2:4;		/* (unused) */
			u_int8_t th_off:4;		/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
			u_int8_t th_off:4;		/* data offset */
			u_int8_t th_x2:4;		/* (unused) */
# endif
			u_int8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
			u_int16_t th_win;		/* window */
			u_int16_t th_sum;		/* checksum */
			u_int16_t th_urp;		/* urgent pointer */
    	} __attribute__ ((__packed__));
    	struct
    	{
			u_int16_t source;
			u_int16_t dest;
			u_int32_t seq;
			u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int16_t res1:4;
			u_int16_t doff:4;
			u_int16_t fin:1;
			u_int16_t syn:1;
			u_int16_t rst:1;
			u_int16_t psh:1;
			u_int16_t ack:1;
			u_int16_t urg:1;
			u_int16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
			u_int16_t doff:4;
			u_int16_t res1:4;
			u_int16_t res2:2;
			u_int16_t urg:1;
			u_int16_t ack:1;
			u_int16_t psh:1;
			u_int16_t rst:1;
			u_int16_t syn:1;
			u_int16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
			u_int16_t window;
			u_int16_t check;
			u_int16_t urg_ptr;
    	};
    };
} __attribute__ ((__packed__));
/*
 * Ps-header struct.
 */
struct ps_header
{
	u_int32_t saddr;
	u_int32_t daddr;
	u_int8_t zero;
	u_int8_t protocol;
	u_int16_t tcp_len; 
} __attribute__ ((__packed__));

u_short checksum (u_short *hdr_pt, int hdr_len)
{
	long sum = 0;
	u_short tmp = 0;
	
	while (hdr_len > 1)
	{
		sum += *hdr_pt++;
		hdr_len -= sizeof (u_short);
	}
	if (hdr_len)
	{
		tmp = *(u_char *) hdr_pt << 8;
		sum += ntohs(tmp);
	}	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (u_short)(~sum);
}
/*
 * Callback function, using in pcap_loop. 
 */
void callback (u_char *arg, const struct pcap_pkthdr *pkthdr,
        const u_char *packet)
{
	int i, j, len, d_len, b_size, high, width, s_count;
	unsigned int sum;
	u_short temp = 0;
	u_char *accum, *buffer, *pkt;
	static int count = 0;
	struct eth_header *eth_hdr;
	struct ip_header *ip_hdr;
	struct tcp_header *tcp_hdr;
	struct ps_header *ps_hdr;
	struct udp_header *udp_hdr;

	printf ("Packet count: %d\n", ++count);
	printf ("Recieved packet size: %d\n", pkthdr -> len);
	printf ("Recieved capture packet size: %d\n", pkthdr -> caplen);
	printf ("This is ASCII:\t\t\t\t\t\t This is HEX:\n");

/* Pretty output info... in progress...
 *
 *	high = pkthdr -> len / 16;
 *	width = pkthdr -> len % 16;
 *	s_count = 0;
 *	for (i = 0; i < pkthdr -> len; i = i + 16)
 *	{
 *		if (s_count < high)
 *		{
 *			for (j = 0; j < LEN; j++)
 *			{
 *				if (isprint(packet[i + j]))
 *				{
 *					printf(" %c ", packet[i + j]);
 *				}
 *				else
 *				{
 *					printf(" . ", packet[i + j]);
 *				}
 *			}
 *			printf("\t");
 *			for (j = 0; j < LEN; j++)
 *			{
 *				printf ("%.2x ", packet[i + j]);
 *			}
 *		}
 *		else
 *		{
 *			for (j = 0; j < LEN; j++)
 *			{
 *				if (isprint(packet[i + j]))
 *				{	
 *					if (j > width) 
 *					{	
 *						printf ("   ");
 *					}
 *					else
 *					{	
 *						printf(" %c ", packet[i + j]);
 *					}	
 *				}
 *				else
 *				{	
 *					if (j > width)
 *					{
 *						printf ("   ");
 *					}
 *					else
 *					{	
 *						printf(" . ", packet[i + j]);
 *					}
 *				}
 *			}
 *			printf("\t");
 *			for (j = 0; j < width; j++)
 *			{
 *				printf ("%.2x ", packet[i + j]);
 *			}	
 *		}
 *	s_count++;	
 *	printf ("\n");
 *	}
 */

/* 
 * Garbage output, using at this moment.
 */
	for (i = 0; i < pkthdr -> len; i = i + 16)
	{
		for (j = 0; j < LEN; j++)
		{
			if (isprint(packet[i + j]))
			{
				printf(" %c ", packet[i + j]);
			} 
			else
			{	
				printf(" . ", packet[i + j]);
			}		
		}
		printf("\t");
		for (j = 0; j < LEN; j++)
		{	
			printf ("%.2x ", packet[i + j]);
		}
	printf ("\n");
	}
/* 
 * Fabricate eth-header and print it.
 */
	eth_hdr = (struct eth_header*) packet;
	printf ("Size of struct eth: %d\n", sizeof(*eth_hdr));
	printf ("Ethernet source: %s\n", ether_ntoa	(eth_hdr -> ether_shost));
	printf ("Ethernet destination: %s\n", ether_ntoa(eth_hdr -> ether_dhost));
/* 
 * Fabricate ip-header and print it, with debugging info.
 */
	ip_hdr = (struct ip_header*)(packet + sizeof(*eth_hdr));
	if ((ip_hdr -> version) != 4)
	{
		printf ("This is not packet are you looking for!\n");
		printf ("-----------------------------------------------------\n");
		return;
	}
	printf ("Size of struct ip: %d\n", ((ip_hdr -> ihl) * 4));
	printf ("IP version: %d\n", ip_hdr -> version);
	printf ("IP source: %s \n", inet_ntoa (ip_hdr -> saddr));
	printf ("IP destination: %s\n", inet_ntoa (ip_hdr -> daddr));
	printf ("TTL: %d ", ip_hdr -> ttl);
	printf ("Check sum: %x ", ip_hdr -> check);
	ip_hdr -> check = 0;
	printf ("My check sum: %x\n",  checksum ((u_short *)ip_hdr, 
            ((ip_hdr -> ihl) * 4)));
/* 
 * Check included protocol. Ignoring UDP.
 */
	if ((ip_hdr -> protocol) == 11)
	{
		printf ("This is UDP packet! Disgusting!\n");
		printf ("-----------------------------------------------------\n");
		return;	
	}
/* 
 * Fabricate TCP-header and print it.
 */
	tcp_hdr = (struct tcp_header *)(packet + sizeof(*eth_hdr) + ((ip_hdr -> ihl) * 4));
	printf ("Size of struct tcp: %d\n", ((tcp_hdr -> th_off) * 4));
	printf ("TCP source: %ld\n", (tcp_hdr -> th_sport));
	printf ("TCP destination: %ld\n", (tcp_hdr -> th_dport));
	printf ("Check sum: %x ", tcp_hdr -> check);
	tcp_hdr -> th_sum = 0;
/* 
 * Fabricate ps-header.
 */
	ps_hdr = malloc (sizeof(struct ps_header));
	ps_hdr -> saddr = ip_hdr -> saddr;
	ps_hdr -> daddr = ip_hdr -> daddr;
	ps_hdr -> zero = 0;
	ps_hdr -> protocol = ip_hdr -> protocol;
	ps_hdr -> tcp_len = ntohs((pkthdr -> len) - sizeof (*eth_hdr) 
            - sizeof (*ip_hdr));
/* 
 * Initiate buffer for count checksum.
 */
	accum = malloc (pkthdr -> len);
	buffer = malloc (pkthdr -> len);
	bzero (buffer, pkthdr -> len);
	bzero (accum, pkthdr -> len);
	memcpy (accum, ps_hdr, sizeof(*ps_hdr));
	memcpy (buffer, packet, pkthdr -> len);
	memcpy (accum + sizeof(*ps_hdr), tcp_hdr, sizeof(*tcp_hdr));
	len = 0;
	len = pkthdr -> len - sizeof (*eth_hdr) - sizeof(*ip_hdr) 
        - sizeof(*tcp_hdr);
	memcpy (accum + sizeof(*ps_hdr) + sizeof(*tcp_hdr), buffer + 
            sizeof (*eth_hdr) + sizeof(*ip_hdr) + sizeof(*tcp_hdr), len);
/*
 * Fabricate checksum.
 */
	d_len = 0;
	d_len = d_len + sizeof(*ps_hdr) + ((tcp_hdr -> th_off) * 4) 
        + ((pkthdr -> len) - sizeof(*eth_hdr) - ((ip_hdr -> ihl) * 4) 
        - ((tcp_hdr -> th_off) * 4));
	printf ("My check sum: %x\n", checksum ((u_short *)accum, d_len));

	printf ("IP_HDR -> IHL: %d, %.2x\n", ip_hdr -> ihl, ip_hdr -> ihl);
	printf ("IP_HDR -> VERSION: %d, %.2x\n", ip_hdr -> version, 
            ip_hdr -> version);
	printf ("IP_HDR -> TOS: %d, %.2x\n", ip_hdr -> tos, ip_hdr -> tos);
	printf ("IP_HDR -> TOT_LEN: %d, %.2x\n", ip_hdr -> tot_len, 
            ip_hdr -> tot_len);
	printf ("IP_HDR -> ID: %d, %.2x\n", ip_hdr -> id, ip_hdr -> id);
	printf ("IP_HDR -> FRAG_OFF: %d, %.2x\n", ip_hdr -> frag_off, 
            ip_hdr -> frag_off);
	printf ("IP_HDR -> TTL: %d, %.2x\n", ip_hdr -> ttl, ip_hdr -> ttl);
	printf ("IP_HDR -> PROTOCOL: %d, %.2x\n", ip_hdr -> protocol, 
            ip_hdr -> protocol);
	printf ("IP_HDR -> CHECK: %d, %.2x\n", ip_hdr -> check, ip_hdr -> check);
	printf ("IP_HDR -> SADDR: %d, %.2x\n", ip_hdr -> saddr, ip_hdr -> saddr);
	printf ("IP_HDR -> DADDR: %d, %.2x\n", ip_hdr -> daddr, ip_hdr -> daddr);
	free (accum);
	free (buffer);
	free (ps_hdr);
	printf ("-----------------------------------------------------\n");
}

int main ()
{
	pcap_t *descr;
	struct pcap_pkthdr pkthdr;
	const u_char *packet;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev (errbuf);
	if (dev == NULL)
	{
		printf ("Device found error!\n");
		exit (1);
	}	
	printf("Device: %s\n", dev);
	descr = pcap_open_live (dev, BUFSIZ, 1, 0, errbuf);
	if (descr == NULL) 
	{
		printf ("Descriptor pcap_t error!\n");
		exit (1);	
	}
	pcap_loop (descr, -1, callback, NULL);
	pcap_close (descr); 
	return 1;
}
