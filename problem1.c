#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h> // for ethernet header
#include <netinet/ip.h>       // for ip header
#include <netinet/udp.h>      // for udp header
#include <netinet/tcp.h>
#include <arpa/inet.h>

FILE* logs;
int main()
{
    logs=fopen("logs.txt","w");

    int sock_r;
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_r < 0)
    {
        printf("error in socket");
        return 0;
    }
    while(1){
    unsigned char *buffer = (unsigned char *)malloc(65536);
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int soddr_len = sizeof(saddr);

    ssize_t buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&soddr_len);

    if (buflen < 0)
    {
        printf("error in reading recvfrom function\n");
        return -1;
    }

    struct ethhdr *eth = (struct ethhdr *)(buffer);
    // printf("\nEthernet Header\n");
    // printf("\t | -Source Address : %d - % d - % d - % d - % d - % d\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    // printf("\t | -Destination Address : % d - % d - % d - % d - % d - % d\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    // printf("\t | -Protocol : % d\n\n", eth->h_proto);
    struct sockaddr_in source, dest;
    unsigned short iphdrlen;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl * 4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    fprintf(logs,"\nIP Header\n");

	// printf("\t|-Version              : %d\n",(unsigned int)ip->version);
	// printf("\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	// printf("\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	// printf("\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	// printf("\t|-Identification    : %d\n",ntohs(ip->id));
	// printf("\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	// printf("\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(logs,"\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(logs,"\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logs,"\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));

    struct tcphdr *tcp=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    fprintf(logs,"\nTCP Header\n");
    fprintf(logs,"\t|-Source Port : %u\n" , ntohs(tcp->source));
    fprintf(logs,"\t|-Destination Port : %u\n" , ntohs(tcp->dest));
    // printf(log_txt , \t|-UDP Length : %d\n  , ntohs(udp->len));
    fprintf(logs,"\t|-TCP Checksum : %d\n", ntohs(tcp->check));
    fprintf(logs,"\t|-TCP Sequence: %d\n", htons(tcp->seq));
    fprintf(logs,"\t|-TCP Window: %d\n", ntohs(tcp->window));
    fprintf(logs,"\t|-TCP Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));


    }
    return 0;
}