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
#include <bits/stdc++.h>
using namespace std;
FILE *logs;
set<vector<string>> s;
int runstate=1;
void handle_ctrlc(int signal)
{
    runstate=0;
}
int main()
{
    logs = fopen("logsq1.txt", "w");
    int sock_r;
    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    // set<vector<string>> s;
    if (sock_r < 0)
    {
        printf("error in socket\n");
        return 0;
    }
    signal(SIGINT,handle_ctrlc);
    while (runstate)
    {
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
        struct sockaddr_in source, dest;
        unsigned short iphdrlen;
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        iphdrlen = ip->ihl * 4;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip->daddr;
        fprintf(logs, "\nTHE 4 TUPLE\n");
        fprintf(logs, "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
        fprintf(logs, "\t|-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
        string source_ips = inet_ntoa(source.sin_addr);
        // cout << source_ips << endl;
        string dest_ip=inet_ntoa(dest.sin_addr);
        struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
        int header_size = sizeof(struct ethhdr) + iphdrlen + tcp->doff * 4;
        // fprintf(logs, "\nTCP Header\n");
        fprintf(logs, "\t|-Source Port : %u\n", ntohs(tcp->source));
        fprintf(logs, "\t|-Destination Port : %u\n", ntohs(tcp->dest));
        string sourceP=to_string((int)ntohs(tcp->source));
        string destP=to_string((int)ntohs(tcp->dest));
        // cout << sourceP<<endl;
        vector<string> temp(4);
        temp[0]=source_ips;
        temp[1]=dest_ip;
        temp[2]=sourceP;
        temp[3]=destP;
        s.insert(temp);
        fprintf(logs, "\n###########################################################");
    }
    cout << "NUMBER OF FLOWS OBSERVED: " <<s.size() << endl;
    cout << "4-TUPLES OF THE FLOWS : \n";
    for(auto it:s)
    {
        cout << "\t Source IP: "<<it[0]<< endl;
        cout << "\t Destination IP: "<<it[1]<< endl;
        cout << "\t Source Port: "<<it[2]<< endl;
        cout << "\t Destination Port: "<<it[3]<< endl;
        cout << endl;
    }
    return 0;
}