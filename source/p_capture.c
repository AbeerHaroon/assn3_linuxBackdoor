#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "p_capture_util.h"
/*
General guidelines by Tim Carstens
1. Deterine the Network Interface to apply libpcap to
2. Initialize a pcap. This is done via file "handles". 
    Similar to opening a file for reading/writing
    we will name our sniffing "session", to tell apart from other sessions
3. When we want to specify specific packets (traffic) to sniff. E.g: UDP, only TCP/IP packets going 
    to specific port etc.
    We must: 
    i.      Create a rule set
    ii.     Compile rule set
    iii.    Apply rule set
    Rule set is kept in a string, then "compiled" to a form that pcap can read.
    Compiling is done via a function within our program.
    Then we apply this compiled rule set to a session we wish to filter.
4. We tell pcap to enter a primary execution loop.
    During this state, pcap waits until it receives the number of packets we the author specify
    Every time pcap receives a packet, pcap calls another function we have defined.
    This function called after receiving a packet can be whateverw design. 
        This can range from printing information, saving packet info to a file etc. (or nothing)
5. After sniffing complete, we close our session and the overall process is complete.

Step 3 (filtering) is optional in essence. We don't NEED to form a rule set.
*/
void pkt_handler_one(u_char *args, const struct pcap_pkthdr* header, const u_char *pkt);
void udp_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_pkt_info(const u_char *pkt, struct pcap_pkthdr pkt_header);

/*To compile:
gcc p_capture.c -lpcap -o sniffer
*/

int main(int argc, char *argv[])
{
    /*Initiating members*/
    char *dev; /*device that is listening*/
    char error_buffer[PCAP_ERRBUF_SIZE]; /*error message*/
    pcap_t *handle; /*pcap_t* to handle sniffing session*/
    const u_char *pkt;
    struct pcap_pkthdr pkt_header;
    int pkt_counter_limit = 1;
    int promic = 0;
    int timeout_limit = 10000; /*in milliseconds*/

    char raw_filter_expr[] = "udp port 5555"; /*filter expression for sniffing*/
    struct bpf_program fP;  /*The compiled filter program*/ 
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    /*Step 1 - Determine an interface*/
    dev = pcap_lookupdev(error_buffer);
    if(dev == NULL) /*If device is NULL*/
    {
        printf("Error finding device%s\n", error_buffer);
        return EXIT_FAILURE;
    }

    /*Determine network number (IP) and netmask number (subnet)*/
    if (pcap_lookupnet(dev, &net, &mask, error_buffer) == -1) {
	    fprintf(stderr, "Can't get netmask for device %s\n", dev);
	    net = 0;
	    mask = 0;
    }

    /*Step 2 - Create sniffer handle*/
    /*Open device for live capture
        on Abeer Haroon system, BUFSIZ is 8192 bytes. Feel free to run buffCheck executable
        Somewhere in libpcap website recommends 65535 bytes if u want all stuff in packet
    */
    handle = pcap_open_live(
        dev,
        BUFSIZ,
        promic,
        timeout_limit,
        error_buffer
    );
    /*Checking if Ethernet headers are supported or not 
    Source: https://www.tcpdump.org/pcap.html
    */
    if (pcap_datalink(handle) != DLT_EN10MB) {
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
	    return(EXIT_FAILURE);
    }

    /* Step 3 (implement a sorter) - Our sniffer is looking for Ethernet packets.
       After that, we check for UDP headers.*/

    if (pcap_compile(handle, &fP, raw_filter_expr, 0, net) == -1) {
	    fprintf(stderr, "Couldn't parse filter %s: %s\n", raw_filter_expr, pcap_geterr(handle));
	    return(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fP) == -1) {
	    fprintf(stderr, "Couldn't install filter %s: %s\n", raw_filter_expr, pcap_geterr(handle));
	    return(EXIT_FAILURE);
    }
    
    /* Extract the payload when each packet arrives*/
    /* Step 4 in an execution loop, we receive each packet. Run a function. Get the data*/
    pcap_loop(handle, 10, handle_UDP, NULL);
    
    /* Step 5 we close our sniffing session*/
    pcap_close(handle);
    return EXIT_SUCCESS;

    /*Attempt to capture one packet
        If no network packet captured AND timeout is reached.
            will return NULL
    */
    // pkt = pcap_next(handle, &pkt_header);
    // if(pkt == NULL)
    // {
    //     printf("no packet found\n");
    //     return EXIT_FAILURE;
    // }

    // /*print packet information*/
    // print_pkt_info(pkt, pkt_header);
}
void pkt_handler_one(u_char *args, const struct pcap_pkthdr* header, const u_char *pkt)
{
    struct ether_header *eth_header;

    /* The pkt is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) pkt;
    
    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        printf("IP\n");
    }
    else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
        printf("ARP\n");
    }
    else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP)
    {
        printf("Reverse ARP\n");
    }

}
/*function to print packet information*/
void print_pkt_info(const u_char *pkt, struct pcap_pkthdr pkt_header)
{
    /*number of bytes available from the capture*/
    printf("Packet capture length %d\n", pkt_header.caplen);
    /*length of packets, in terms of bytes */
    printf("Packet total length %d\n", pkt_header.len);
}