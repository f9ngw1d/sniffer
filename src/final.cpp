#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"
#define APP_COPYRIGHT "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length(maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet address are 6 bytes */
#define ETHER_ADDR_LEN 6

#define URL_MAX_LEN 65536
#define MAX_HOST_LEN 1024
#define MAX_GET_LEN 2048

#define get_u_int8_t(X, O) (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u_int16_t(X, O) (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u_int32_t(X, O) (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u_int64_t(X, O) (*(uint64_t *)(((uint8_t *)X) + O))

/* Ethernet header */
struct sniff_ethernet
{
        u_char ether_dhost[ETHER_ADDR_LEN]; /* dest host addr */
        u_char ether_shost[ETHER_ADDR_LEN]; /* sour host addr */
        u_short ether_type;                 /* IP ARP RARP ? */
};

struct httppacket
{
        char *source_ip;
        char *dest_ip;
        char *source_port;
        char *dest_port;
        char *host;
        char id[10];
        char *time;
};
/* IP header */
struct sniff_ip
{
        u_char ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char ip_tos;                 /* type of service */
        u_short ip_len;                /* total length */
        u_short ip_id;                 /* identification */
        u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000                   /* reserved fragment flag */
#define IP_DF 0x4000                   /* dont fragment flag */
#define IP_MF 0x2000                   /* more fragments flag */
#define IP_OFFMASK 0x1fff              /* mask for fragmenting bits */
        u_char ip_ttl;                 /* time to live */
        u_char ip_p;                   /* protocol */
        u_short ip_sum;                /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
        u_short th_sport; /* source port */
        u_short th_dport; /* destination port */
        tcp_seq th_seq;   /* sequence number */
        tcp_seq th_ack;   /* acknowledgement number */
        u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
        u_short th_win; /* window */
        u_short th_sum; /* checksum */
        u_short th_urp; /* urgent pointer */
};

void print_app_usage(void);

/*
 * print help text
 */
void print_app_usage(void)
{
        printf("Usage: %s [interface]\n", APP_NAME);
        printf("\n");
        printf("Options:\n");
        printf("    interface    Listen on <interface> for packets.\n");
        printf("\n");

        return;
}
void substring(char *s, char ch1, char ch2, char *substr)
{
        while (*s && *s++ != ch1)
                ;
        while (*s && *s != ch2)
                *substr++ = *s++;
        *substr = '\0';
}

/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        struct sniff_ethernet *ethernet;
        struct sniff_ip *ip;
        struct sniff_tcp *tcp;
        const char *payload;
        char temp[1000];
        int *counter = (int *)arg;
        const char *ch;

        struct httppacket p;
        ethernet = (struct sniff_ethernet *)(packet);
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + sizeof(struct sniff_ip));
        payload = (const char *)(packet + SIZE_ETHERNET + sizeof(struct sniff_ip) + sizeof(struct sniff_tcp));
        if (strstr(payload, "HTTP") != NULL)
        {
                printf("number of packet:%d\n", ++(*counter));
                //printf("%s\n",payload);
                /* print source and destination IP addresses */

                printf("From: %s\n", inet_ntoa(ip->ip_src));
                printf("To: %s\n", inet_ntoa(ip->ip_dst));

                printf("Src port: %d\n", ntohs(tcp->th_sport));
                printf("Dst port: %d\n", ntohs(tcp->th_dport));
                //	printf("%s\n\n",payload);
                //	itoa(counter,p.id,10);
                p.source_ip = (char *)inet_ntoa(ip->ip_src);
                p.dest_ip = (char *)inet_ntoa(ip->ip_dst);
                p.source_port = (char *)ntohs(tcp->th_sport);
                p.dest_port = (char *)ntohs(tcp->th_dport);

                ch = payload;
                printf("%d\n", strlen((char *)ch));
                int i, j;
                int flag = 1;
                int pos;
                char url[100];
                char server[30];
                char hooo[30];
                for (j = 0, i = 0; i < strlen((char *)ch); i++)
                {
                        if (ch[i] != '\n')
                        {
                                flag = 1;
                                temp[j] = ch[i];
                                j++;
                        }
                        else
                        {
                                temp[j] = '\0';
                                //		printf("%s\n",temp);
                                if (strstr(temp, "Host:"))
                                {
                                        substring(temp, ':', '\0', hooo);
                                }
                                else if (strstr(temp, "HTTP"))
                                {
                                        substring(temp, ' ', ' ', server);
                                }
                                j = 0;
                                if (flag == 0)
                                        break;
                                flag = 0;
                        }
                }
                //		strcat(hooo,server);
                //		printf("%s\n",p.id);
                printf("url: %s\n", hooo);
                printf("%s\n ", server);
        }

        return;
}

int main(int argc, char **argv)
{
        int count = 0;
        char *dev = NULL;              /* capture device name */
        char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
        pcap_t *handle;                /* packet capture handle */

        char filter_exp[] = ""; /* filter expression [3] */
        struct bpf_program fp;                                   /* compiled filter program (expression) */
        bpf_u_int32 mask;                                        /* subnet mask */
        bpf_u_int32 net;                                         /* ip */
        int num_packets = 500;                                   /* number of packets to capture */

        /* check for capture device name on command-line */
        if (argc == 2)
        {
                dev = argv[1];
        }
        else if (argc > 2)
        {
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                print_app_usage();
                exit(EXIT_FAILURE);
        }
        else
        {
                /* find a capture device if not specified on command-line */
                dev = pcap_lookupdev(errbuf);
                if (dev == NULL)
                {
                        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                        exit(EXIT_FAILURE);
                }
        }

        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }

        /* print capture info */
        //printf("Device: %s\n", dev);
        //printf("Number of packets: %d\n", num_packets);
        //printf("Filter expression: %s\n", filter_exp);

        /* open capture device */
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }

        /* make sure we're capturing on an Ethernet device [2] */
        if (pcap_datalink(handle) != DLT_EN10MB)
        {
                fprintf(stderr, "%s is not an Ethernet\n", dev);
                exit(EXIT_FAILURE);
        }

        /* compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1)
        {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }
        while (count < 500)
        {
                /* now we can set our callback function */
                pcap_loop(handle, num_packets, processPacket, (u_char *)&count);
        }

        /* cleanup */
        pcap_freecode(&fp);
        pcap_close(handle);

        printf("\nCapture complete.\n");

        return 0;
}