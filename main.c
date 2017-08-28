/*
 * main.c
 *
 *  Created on: 2017年8月14日
 *      Author: hblzxsj
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define MAX 1024

int serverPort;
char *serverHost;
in_addr_t serverAddr;

typedef struct {
	u_int len:24;
	u_int no:8;
	u_int cmd:8;
	unsigned char params;
} mysql_payload;

typedef struct {
	u_int len:24;
	u_int no:8;
	u_int type:8;
} mysql_response;

typedef struct {
	unsigned char field_cnt;
	unsigned char extra_info;
} mysql_result_set_hdr;

typedef struct {
	mysql_result_set_hdr *hdr;
} mysql_result_set;

int call(u_char *argument, const struct pcap_pkthdr* pack,
		const u_char *content) {
	int m = 0, n;
	const u_char *buf, *iphead;
	u_char *p;
	struct ether_header *ethernet;
	struct ip *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmp *icmp;
	struct timeval tm;
	int len = pack->len;
	buf = content;
	//printf("==================================================\n");
	/*printf("The Frame is \n");
	while (m < (pack->len)) {
		printf("%02x", buf[m]);
		m = m + 1;
		if (m % 16 == 0)
			printf("\n");
		else
			printf(":");
	}
	printf("\n");*/
	//printf("Grabbed packet of length %d\n", pack->len);
	//printf("Recieved at ..... %s", ctime((const time_t*) &(pack->ts.tv_sec)));
//  printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

	ethernet = (struct ether_header *) content;
	p = ethernet->ether_dhost;
	n = ETHER_ADDR_LEN;
	//printf("Dest MAC is:");
	do {
		//printf("%02x:", *p ++);
	} while (--n > 0);
	//printf("\n");
	p = ethernet->ether_shost;
	n = ETHER_ADDR_LEN;
	//printf("Source MAC is:");
	do {
		//printf("%02x:", *p ++);
	} while (--n > 0);
	//printf("\n");

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		//printf("It's a IP packet\n");
		ip = (struct ip *) (content + sizeof(struct ether_header));
		len -= sizeof(struct ether_header);
		if (ip->ip_v != 4) {
			//not support ipv6 now
			return 0;
		}
		//printf("IP Version:%d\n", ip->ip_v);
		//printf("TTL:%d\n", ip->ip_ttl);
		//printf("Source address:%s\n", inet_ntoa(ip->ip_src));
		//printf("Destination address:%s\n", inet_ntoa(ip->ip_dst));
		//printf("Protocol:%d\n", ip->ip_p);
		switch (ip->ip_p) {
			case 6:
				//printf("The Transport Layer Protocol is TCP\n");
				tcp = (struct tcphdr*) ((unsigned char *)ip + ip->ip_hl * 4);
				len -= ip->ip_hl * 4;
				//printf("Source Port:%d\n", ntohs(tcp->th_sport));
				//printf("Destination Port:%d\n", ntohs(tcp->th_dport));
				//printf("Sequence Number:%u\n", ntohl(tcp->th_seq));
				//deal with data
				len -= tcp->th_off * 4;
				if (len > 0) {
					mysql_payload *payload = (unsigned char *)tcp + tcp->th_off * 4;
					gettimeofday(&tm, NULL);
					long tm_ms = tm.tv_sec * 1000 + tm.tv_usec / 1000.0;
					if (serverAddr == ip->ip_dst.s_addr && ntohs(tcp->th_dport) == serverPort) {
						//request
						if (payload->cmd == 0x03) {
							//cmd_query
							char sql[len];
							memset(sql, 0, len);
							memcpy(sql, &payload->params, payload->len - 1);
							printf("%ld\t%s:%d\t%s:%d\t", tm_ms, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
							printf("%s", sql);
							printf("\tLINE_END\n");
						}
					} else {
						//reponse
						printf("%ld\t%s:%d\t%s:%d\t", tm_ms, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
						mysql_response *response = (mysql_response *)payload;
						if (response->type == 0x00) {
							//ok
							printf("ok");
							m = 0;
						} else if (response->type == 0xff) {
							//error
							printf("error");
						} else if (response->type == 0xfe) {
							//eof;
							printf("eof");
						} else {
							//response
							printf("data");
						}
						printf("\tLINE_END\n");
					}
					/*m = 0;
					while (m < len) {
						printf("%02x", ((unsigned char *)payload)[m]);
						m = m + 1;
						if (m % 16 == 0)
							printf("\n");
						else
							printf(":");
					}
					printf("\n");*/
				} else {
					//no user data
					/*printf("The Frame is \n");
					m = 0;
					while (m < (pack->len)) {
						printf("%02x", buf[m]);
						m = m + 1;
						if (m % 16 == 0)
							printf("\n");
						else
							printf(":");
					}
					printf("\n");*/
				}
				break;
			case 17:
				printf("The Transport Layer Protocol is UDP\n");
				udp = (struct udphdr*) ((unsigned char *)ip + ip->ip_hl * 4);
				len -= ip->ip_hl * 4;
				printf("Source port:%d\n", ntohs(udp->uh_sport));
				printf("Destination port:%d\n", ntohs(udp->uh_dport));
				break;
			case 1:
				printf("The Transport Layer Protocol is ICMP\n");
				icmp = (struct icmp*) ((unsigned char *)ip + ip->ip_hl * 4);
				len -= ip->ip_hl * 4;
				printf("ICMP Type:%d\n", icmp->icmp_type);
				switch (icmp->icmp_type) {
					case 8:
						printf("ICMP Echo Request Protocol\n");
						break;
					case 0:
						printf("ICMP Echo Reply Protocol\n");
						break;
					default:
						break;
				}
				break;
			default:
				break;
		}
		/*      if(*iphead==0x45)
		 {
		 printf("Source ip :%d.%d.%d.%d\n",iphead[12],iphead[13],iphead[14],iphead[15]);
		 printf("Dest ip :%d.%d.%d.%d\n",iphead[16],iphead[17],iphead[18],iphead[19]);

		 }*/
//      tcp= (struct tcp_header*)(iphead);
//      source_port = ntohs(tcp->tcp_source_port);
//      dest_port = ntohs(tcp->tcp_destination_port);
	} else if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP) {
		printf("This is ARP packet.\n");
		iphead = buf + sizeof(struct ether_header);
		if (*(iphead + 2) == 0x08) {
			printf("Source ip:\t %d.%d.%d.%d\n", iphead[14], iphead[15],
					iphead[16], iphead[17]);
			printf("Dest ip:\t %d.%d.%d.%d\n", iphead[24], iphead[25],
					iphead[26], iphead[27]);
			printf("ARP TYPE: %d (0:request;1:respond)\n", iphead[6]);

		}
	}
	return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet) {
	printf("on packet\n");
}

int main(int argc, char *argv[]) {
	pcap_t *pcap = 0;
	const char *dev = "en0";
	char filter_str[512] = {0};
	char errbuf[PCAP_ERRBUF_SIZE];
	int status;
	const char *filter = "host %s and port %d";
	struct bpf_program fp;
	if (argc != 3) {
		printf("usage: mysql_analytics <mysql host ip> <port>\n");
		return 1;
	}
	serverHost = argv[1];
	serverPort = atoi(argv[2]);
	serverAddr = inet_addr(serverHost);
	sprintf(filter_str, filter, serverHost, serverPort);
	printf("filter: %s\n", filter_str);
	pcap = pcap_create(dev, errbuf);
	if (pcap == NULL) {
		printf("device not found\n");
		return 1;
	}
	pcap_set_immediate_mode(pcap, 1);
	pcap_set_snaplen(pcap, 1024);
	pcap_set_promisc(pcap, 0);
	pcap_set_timeout(pcap, 1000);
	pcap_set_buffer_size(pcap, 256000);
	status = pcap_activate(pcap);
	if (status != 0) {
		printf("activate failed\n");
		return 2;
	}
	status = pcap_compile(pcap, &fp, filter_str, 0, 0);
	if (status != 0) {
		printf("filter compile failed, please check it.\n");
		return 3;
	}
	status = pcap_setfilter(pcap, &fp);
	if (status != 0) {
		printf("filter setting failed, please check it.\n");
		return 4;
	}
	pcap_loop(pcap, 0, call, NULL);

	return 0;
}

