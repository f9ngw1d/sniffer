
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "parser.h"
#include "package.h"

void print_app_usage(void);
void substring( char *s, char ch1, char ch2, char *substr ); 
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet);