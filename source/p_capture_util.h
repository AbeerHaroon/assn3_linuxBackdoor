/*Header file that will contain structure info for 
IP, TCP and UDP packets.

This utility will process through the packets also. 
UDP implemented first, then TCP, then IP 

*/
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/types.h>
#include <sys/socket.h>

#define SIZE_ETHERNET 14


// tcpdump header (ether.h) defines ETHER_HDRLEN) 
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

/*Function prototypes
Copy-Pasted from Aman Abdulla's examples*/
u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_TCP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);

/*
 * Copy-Pasted from Aman Abdulla's pkt_sniffer.h header file.
 *      Also influenced by tcpdump and Martin Casado
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct aman_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct aman_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #defi#define SIZE_ETHERNET 14


// tcpdump header (ether.h) defines ETHER_HDRLEN) 
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endifrt th_urp;                 /* urgent pointer */
};

/* UDP header structure copied from tcpdump source
options not included.*/
struct crude_udp {
        u_int16_t	uh_sport;		/* source port */
	u_int16_t	uh_dport;		/* destination port */
	u_int16_t	uh_ulen;		/* udp length */
	u_int16_t	uh_sum;			/* udp checksum - 16 bits */
};