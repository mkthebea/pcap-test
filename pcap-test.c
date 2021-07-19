#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_eth(const u_char* packet) {
    struct libnet_ethernet_hdr hdr;
    memcpy(&hdr, packet, sizeof (hdr));
    printf("\n\n[Ethernet Header] src mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x    ",hdr.ether_shost[0],hdr.ether_shost[1],hdr.ether_shost[2],hdr.ether_shost[3],hdr.ether_shost[4],hdr.ether_shost[5]);
    printf("dst mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",hdr.ether_dhost[0],hdr.ether_dhost[1],hdr.ether_dhost[2],hdr.ether_dhost[3],hdr.ether_dhost[4],hdr.ether_dhost[5]);
    return;
}

void print_ip(const u_char* packet) {
    struct libnet_ipv4_hdr hdr;
    memcpy(&hdr, &packet[14], sizeof (hdr));
    int si = ntohl(hdr.ip_src.s_addr);
    int di = ntohl(hdr.ip_dst.s_addr);
    printf("\n[IP Header] src ip: %d.%d.%d.%d    ",(si&0xFF000000) >> 24, (si&0x00FF0000) >> 16, (si&0x0000FF00) >> 8, si&0x000000FF);
    printf("dst ip: %d.%d.%d.%d\n",(di&0xFF000000) >> 24, (di&0x00FF0000) >> 16, (di&0x0000FF00) >> 8, di&0x000000FF);
    return;
}

void print_tcp(const u_char* packet) {
    struct libnet_tcp_hdr hdr;
    memcpy(&hdr, &packet[34], sizeof (hdr));
    printf("\n[TCP Header] src port: %d    ",ntohs(hdr.th_sport));
    printf("dst port: %d\n",ntohs(hdr.th_dport));
    return;
}

void print_data(const u_char* packet, int totlen) {
    if (totlen <= 54)
        printf("\n[Data]\n\n");
    else {
        printf("\n[Data] ");
        for(int i=0;i<8;i++)
            printf("%.2x ", packet[54 + i]);
        printf("\n\n");
    }
    return;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    while (true) {
        struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        if(packet[23] != 0x06)
            continue;

        printf("§====================================================================================§");
        print_eth(packet);
        print_ip(packet);
        print_tcp(packet);
        print_data(packet, header->caplen);
    }

	pcap_close(pcap);
}
