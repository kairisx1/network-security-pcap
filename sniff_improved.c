#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; // destination MAC
    u_char  ether_shost[6]; // source MAC
    u_short ether_type;     // protocol type (IP, ARP, etc)
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, // IP header length
                       iph_ver:4; // IP version
    unsigned char      iph_tos;   // Type of service
    unsigned short int iph_len;   // IP total length
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;   // Time to live
    unsigned char      iph_protocol; // Protocol
    unsigned short int iph_chksum;   // Checksum
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;   // Source port
    u_short tcp_dport;   // Destination port
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;   // Data offset + reserved bits
#define TH_OFF(th) (((th)->tcp_offx2 & 0xF0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Only process IP packets
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // Only process TCP packets
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

            // Calculate header lengths
            int ip_header_len = ip->iph_ihl * 4;
            int tcp_header_len = TH_OFF(tcp) * 4;
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

            printf("\n========= TCP Packet Captured =========\n");

            // Print Ethernet MAC addresses
            printf("Ether Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Ether Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // Print IP addresses
            printf("IP Src: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("IP Dst: %s\n", inet_ntoa(ip->iph_destip));

            // Print TCP ports
            printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // Print first 30 bytes of payload
            int total_headers_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_size = header->caplen - total_headers_size;
            if (payload_size > 0) {
                printf("Payload (%d bytes): ", payload_size);
                for (int i = 0; i < payload_size && i < 30; i++) {
                    printf("%c", isprint(payload[i]) ? payload[i] : '.');
                }
                printf("\n");
            } else {
                printf("No Payload\n");
            }

            printf("=======================================\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // <-- TCP 필터링으로 변경
    bpf_u_int32 net;

    // Open live capture on interface
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Compile and set filter
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error setting filter");
        exit(EXIT_FAILURE);
    }

    // Start packet processing loop
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

