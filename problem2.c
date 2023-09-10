#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h> // for ethernet header
#include <netinet/ip.h>       // for ip header
#include <netinet/udp.h>      // for udp header
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
FILE *logs;
void PrintData(const unsigned char *data, int Size)
{
    int i, j;
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0) // if one line of hex printing is complete...
        {
            fprintf(logs, "         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logs, "%c", (unsigned char)data[j]); // if its a number or alphabet

                else
                    fprintf(logs, "."); // otherwise print a dot
            }
            fprintf(logs, "\n");
        }

        if (i % 16 == 0)
            fprintf(logs, "   ");
        fprintf(logs, " %02X", (unsigned int)data[i]);

        if (i == Size - 1) // print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                fprintf(logs, "   "); // extra spaces
            }

            fprintf(logs, "         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    fprintf(logs, "%c", (unsigned char)data[j]);
                }
                else
                {
                    fprintf(logs, ".");
                }
            }

            fprintf(logs, "\n");
        }
    }
}
int main()
{
    logs = fopen("logsq2.txt", "w");
    time_t endwait;
    time_t start = time(NULL);
    time_t seconds = 5000; 

    endwait = start + seconds;
    int sock_r;
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_r < 0)
    {
        printf("error in socket\n");
        return 0;
    }
    // map<int,vector<string>> mp;
    while (start < endwait)
    {
        start = time(NULL);
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
        fprintf(logs, "\nEthernet Header\n");
        fprintf(logs, "\t | -Source Address : %d - % d - % d - % d - % d - % d\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        fprintf(logs, "\t | -Destination Address : % d - % d - % d - % d - % d - % d\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        fprintf(logs, "\t | -Protocol : % d\n\n", eth->h_proto);
        struct sockaddr_in source, dest;
        unsigned short iphdrlen;
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        iphdrlen = ip->ihl * 4;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;

        fprintf(logs, "\nIP Header\n");

        fprintf(logs, "\t|-Header Checksum   : %d\n", ntohs(ip->check));
        fprintf(logs, "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
        fprintf(logs, "\t|-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));

        struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
        int header_size = sizeof(struct ethhdr) + iphdrlen + tcp->doff * 4;
        fprintf(logs, "\nTCP Header\n");
        fprintf(logs, "\t|-Source Port : %u\n", ntohs(tcp->source));
        fprintf(logs, "\t|-Destination Port : %u\n", ntohs(tcp->dest));
        // printf(log_txt , \t|-UDP Length : %d\n  , ntohs(udp->len));
        fprintf(logs, "\t|-TCP Checksum : %d\n", ntohs(tcp->check));
        fprintf(logs, "IP Header\n");
        PrintData(buffer, iphdrlen);

        fprintf(logs, "TCP Header\n");
        PrintData(buffer + iphdrlen, tcp->doff * 4);

        fprintf(logs, "Data Payload\n");
        PrintData(buffer + header_size, buflen - header_size);

        fprintf(logs, "\n###########################################################");
    }
    return 0;
}