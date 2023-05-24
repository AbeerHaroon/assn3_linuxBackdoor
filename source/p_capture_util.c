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

#include "p_capture_util.h"

u_int16_t handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	u_int caplen = pkthdr->caplen;
    	u_int length = pkthdr->len;
    	struct ether_header *eptr;  /* net/ethernet.h */
    	u_short ether_type;

    	if (caplen < ETHER_HDRLEN)
    	{
        	fprintf(stdout,"Packet length less than ethernet header length\n");
        	return -1;
    	}

    	// Start with the Ethernet header... 
    	eptr = (struct ether_header *) packet;
    	ether_type = ntohs(eptr->ether_type);

    	// Print SOURCE DEST TYPE LENGTH fields
   	printf ("\n");
	fprintf(stdout,"ETH: ");
    	fprintf(stdout,"%s ", ether_ntoa((struct ether_addr*)eptr->ether_shost));
    	fprintf(stdout,"%s ",ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    	// Check to see if we have an IP packet 
    	if (ether_type == ETHERTYPE_IP)
    	{
        	printf ("\n");
		fprintf(stdout,"(IP)");
    	}
	else  if (ether_type == ETHERTYPE_ARP)
    	{
        	fprintf(stdout,"(ARP)");
    	}
	else  if (eptr->ether_type == ETHERTYPE_REVARP)
    	{
        	fprintf(stdout,"(RARP)");
    	}
	else 
	{
        	fprintf(stdout,"(?)");
    	}
    	fprintf(stdout," %d\n",length);

    	return ether_type;
}

// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	const struct aman_ip* ip;
    	u_int length = pkthdr->len;
    	u_int hlen,off,version;
    	int len;
	
    	// Jump past the Ethernet header 
    	ip = (struct aman_ip*)(packet + sizeof(struct ether_header));
    	length -= sizeof(struct ether_header); 

    	// make sure that the packet is of a valid length 
    	if (length < sizeof(struct aman_ip))
    	{
        	printf ("Truncated IP %d",length);
        	exit (1);
    	}

    	len     = ntohs(ip->ip_len);
    	hlen    = IP_HL(ip); 	// get header length 
    	version = IP_V(ip);	// get the IP version number

    	// verify version 
    	if(version != 4)
    	{
      		fprintf(stdout,"Unknown version %d\n",version);
      		exit (1); 
        }

    	// verify the header length */
    	if(hlen < 5 )
    	{
        	fprintf(stdout,"Bad header length %d \n",hlen);
    	}

    	// Ensure that we have as much of the packet as we should 
    	if (length < len)
        	printf("\nTruncated IP - %d bytes missing\n",len - length);

    	// Ensure that the first fragment is present
    	off = ntohs(ip->ip_off);
    	if ((off & 0x1fff) == 0 ) 	// i.e, no 1's in first 13 bits 
    	{				// print SOURCE DESTINATION hlen version len offset */
        	fprintf(stdout,"IP: ");
        	fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
        	fprintf(stdout,"%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen,version,len,off);
    	}
    	
    	switch (ip->ip_p) 
        {
                case IPPROTO_TCP:
                        printf("   Protocol: TCP\n");
			handle_TCP (args, pkthdr, packet);
                break;
                case IPPROTO_UDP:
                        printf("   Protocol: UDP\n");
                break;
                case IPPROTO_ICMP:
                        printf("   Protocol: ICMP\n");
                break;
                case IPPROTO_IP:
                        printf("   Protocol: IP\n");
                break;
                default:
                        printf("   Protocol: unknown\n");
                break;
        }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	const struct aman_tcp *tcp=0;          // The TCP header 
	const struct aman_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload 

  	int size_ip;
    int size_tcp;
    int size_payload;
	
	printf ("\n");
	printf ("TCP packet\n");
  
    ip = (struct aman_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip)*4;
       
    // define/compute tcp header offset
    tcp = (struct aman_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
        
    if (size_tcp < 20) 
	{
        printf("   * Control Packet? length: %u bytes\n", size_tcp);
        exit(1);
    }
               
    printf ("   Src port: %d\n", ntohs(tcp->th_sport));
    printf ("   Dst port: %d\n", ntohs(tcp->th_dport));
        
    // define/compute tcp payload (segment) offset
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
         
        
    // Print payload data, including binary translation 
         
    if (size_payload > 0) 
	{
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload (payload, size_payload);
    }
}

void handle_UDP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct crude_udp *udp = 0;        // The UDP header 
	const struct aman_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload 

    int size_ip;
    int size_udp;
    int size_payload;
	
	printf ("\n");
	printf ("UDP packet\n");
    
    //after IP header = total size from IP - 4*ip_Header length
    

    ip = (struct aman_ip*)(packet + SIZE_ETHERNET); //cast pointer to a byte in memory that is 
                                                        //start of packet + SIZE_ETHERNET (14 bytes)
    size_ip = IP_HL (ip)*4; //size of the IP header
                                //Header length tels the size of header in terms of 4-byte chunks
                                //therefore, multiplying say 2*4 = tells us 8 bytes cuz two 4B chunks

    // define/compute udp header offset
    udp = (struct crude_udp*)(packet + SIZE_ETHERNET + size_ip);
    //full_udp_size = udp_length
    full_udp_size = ntohs(udp->uh_ulen); //length is in bytes
    //src_port = 2 bytes
    //dst_port = 2 bytes
    //checksum = 2 bytes
    //data = full_udp_size - src_port - dst_port - checksum - length
    size_udp = (2*2) + 2 + 2;//(src_port + dst_port) + checksum + length. szie of UDP header
    num_bytes_udp_data = full_udp_size - size_udp; //number of bytes in data of UDP packet

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

    // compute udp payload (segment) size
    //IP length has the whole IP header plus data
    //IP length - UDP and IP header lengths to acquire the size of the payload
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
         
    // Print payload data, including binary translation 
         
    if (size_payload > 0) 
	{
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload (payload, size_payload);
    }
}

// This function will print payload data
void print_payload (const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;			// offset counter 
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// does data fits on one line?
	if (len <= line_width) 
        {
		print_hex_ascii_line (ch, len, offset);
		return;
	}

	// data spans multiple lines 
	for ( ;; ) 
        {
		// determine the line length and print
		line_len = line_width % len_rem;
		print_hex_ascii_line (ch, line_len, offset);
		
                // Process the remainder of the line 
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;
		
                // Ensure we have line width chars or less
		if (len_rem <= line_width) 
                {
			//print last line
			print_hex_ascii_line (ch, len_rem, offset);
			break;
		}
	}
 }

// Print data in hex & ASCII
void print_hex_ascii_line (const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	// the offset
	printf("%05d   ", offset);
	
	// print in hex 
	ch = payload;
	for (i = 0; i < len; i++) 
        {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
                    printf(" ");
	}
	
	// print spaces to handle a line size of less than 8 bytes 
	if (len < 8)
		printf(" ");
	
	// Pad the line with whitespace if necessary  
	if (len < 16) 
        {
		gap = 16 - len;
		for (i = 0; i < gap; i++) 
                    printf("   ");
        }
	printf("   ");
	
	// Print ASCII
	ch = payload;
	for (i = 0; i < len; i++) 
        {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf ("\n");

 }
