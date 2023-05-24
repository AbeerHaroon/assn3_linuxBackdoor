/* 
    Demo file to run and test libpcap library
    Author: Abeer Haroon

    compile with:
    gcc demo.c -lpcap
*/
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        fprintf(stderr, "Could not find default device: %s\n", errbuf);
        return(EXIT_FAILURE);
    }

    printf("Device: %s\n", dev);

    // pcap_t *handle;
    // handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    // if(handle == NULL)
    // {
    //     fprintf(stderr, "Could not open device %s: %s\n", dev,errbuf);
    //     return(EXIT_FAILURE);
    // }
    
    // printf("returned a pcap_t\n");
    
    /*Get info from dev (device)*/
    int lookup_res;
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /*IP Address as integer*/
    bpf_u_int32 subnet_mask_raw; /*Subnet mask as integer*/
    //errbuf exists 
    struct in_addr address; /*Used for both IP and Subnet*/

    lookup_res = pcap_lookupnet(
        dev,
        &ip_raw,
        &subnet_mask_raw,
        errbuf
    );
    if(lookup_res == -1)
    {
        printf("%s\n",errbuf);
        return EXIT_FAILURE;
    }

    /* If you call inet_ntoa() more than once
    you will overwrite the buffer. If we only stored
    the pointer to the string returned by inet_ntoa(),
    and then we call it again later for the subnet mask,
    our first pointer (ip address) will actually have
    the contents of the subnet mask. That is why we are
    using a string copy to grab the contents while it is fresh.
    The pointer returned by inet_ntoa() is always the same.

    This is from the man:
    The inet_ntoa() function converts the Internet host address in,
    given in network byte order, to a string in IPv4 dotted-decimal
    notation. The string is returned in a statically allocated
    buffer, which subsequent calls will overwrite. */

    /*Get ip in human readable form*/
    address.s_addr = ip_raw;
    strcpy(ip,inet_ntoa(address));
    if(ip == NULL)
    {
        perror("inet_ntoa()\n");
        return EXIT_FAILURE;
    }
    
    /*get subnet mask in human readable form*/
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask,inet_ntoa(address));
    if(subnet_mask == NULL)
    {
        perror("inet_ntoa\n");
        return EXIT_FAILURE;
    }
    
    printf("Device: %s\n", dev);
    printf("IP Address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

    return(EXIT_SUCCESS);
}