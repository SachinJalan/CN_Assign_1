#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <bits/stdc++.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h> // for ethernet header
#include <netinet/ip.h>       // for ip header
#include <netinet/udp.h>      // for udp header
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
using namespace std;
FILE *logs;
FILE *pid_data;
map<int, set<string>> port_to_pid;
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
void print_pid(int port_id)
{
    int port = port_id; // Replace with your desired port number
    // Construct the command dynamically with the port variable
    char command[128]; // Adjust the buffer size as needed
    snprintf(command, sizeof(command), "ss -nap | grep ':%d ' | grep -oP 'pid=\\K\\d+'", port);

    // Open a pipe to the command
    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen");
        return;
    }

    char output[128]; // Adjust the buffer size as needed
    if (fgets(output, sizeof(output), fp) != NULL)
    {
        // Remove the trailing newline character, if present
        size_t len = strlen(output);
        if (len > 0 && output[len - 1] == '\n')
        {
            output[len - 1] = '\0';
        }
        string str = "";
        for (int i = 0; i < len; i++)
        {
            str += output[i];
        }
        if (port_to_pid.find(port_id) != port_to_pid.end())
            port_to_pid[port_id].insert(str);
        else
        {
            port_to_pid.insert({port_id, {str}});
        }
        fprintf(pid_data, "Extracted number: %s for port number: %d\n", output, port_id);
    }
    else
    {
        fprintf(pid_data, "No match found for port %d\n", port_id);
    }

    pclose(fp);
}
int main()
{
    logs = fopen("logsp3.txt", "w");
    pid_data = fopen("pid_data.txt", "w");
    time_t endwait;
    time_t start = time(NULL);
    time_t seconds = 30; // end loop after this time has elapsed

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
        print_pid((int)ntohs(tcp->source));
        fprintf(logs, "\t|-Source Port : %u\n", ntohs(tcp->source));
        fprintf(logs, "\t|-Destination Port : %u\n", ntohs(tcp->dest));
        fprintf(logs, "\t|-TCP Checksum : %d\n", ntohs(tcp->check));
        fprintf(logs, "IP Header\n");
        PrintData(buffer, iphdrlen);

        fprintf(logs, "TCP Header\n");
        PrintData(buffer + iphdrlen, tcp->doff * 4);

        fprintf(logs, "Data Payload\n");
        PrintData(buffer + header_size, buflen - header_size);

        fprintf(logs, "\n###########################################################");
        // sleep(1);
    }
    while (1)
    {
        printf("Enter the port number to find its pids:");
        int inp_port;
        scanf("%d", &inp_port);
        if (port_to_pid.find(inp_port) == port_to_pid.end())
        {
            printf("Invalid Port Number\n");
        }
        else
        {
            printf("Following are the PIDs\n");
            for (auto it : port_to_pid[inp_port])
            {
                cout << it << " ";
            }
            cout << endl;
        }
    }
    return 0;
}