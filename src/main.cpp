#include "final.h"
#define SNAP_LEN 1518
int main(int argc, char **argv)
{
	int count=0;	
	char *dev = NULL;   /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
	pcap_t *handle;    /* packet capture handle */

	char filter_exp[] = "ip[6:2]&0x1fff=0 and dst port 80 ";  /* filter expression [3] */
	struct bpf_program fp;   /* compiled filter program (expression) */
	bpf_u_int32 mask;   /* subnet mask */
	bpf_u_int32 net;   /* ip */
	int num_packets = 500;   /* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
			exit(EXIT_FAILURE);
		}
	}
 
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	//printf("Device: %s\n", dev);
	//printf("Number of packets: %d\n", num_packets);
	//printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	while(count < 500){
		/* now we can set our callback function */
		pcap_loop(handle, num_packets, processPacket, (u_char *)&count);
	}

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
