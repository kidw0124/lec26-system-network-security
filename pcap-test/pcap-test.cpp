//pcap-test.cpp
#include"pcap-test.h"
void print_ethernet_mac(libnet_ethernet_hdr*ethernet){
	puts("-----------Ethernet Header-----------");
	printf("src mac is ");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		if(i)printf(":");
		printf("%02x",ethernet->ether_shost[i]);
	}
	printf("\n");
	printf("dst mac is ");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		if(i)printf(":");
		printf("%02x",ethernet->ether_dhost[i]);
	}
	printf("\n");
	puts("-------------------------------------");
}

void print_ip(libnet_ipv4_hdr*ipv4){
	puts("-----------IP Header-----------");
	printf("src ip is ");
	for(int i=0;i<IP_ADDR_LEN;i++){
		if(i)printf(".");
		printf("%d",ipv4->ip_src[i]);
	}
	printf("\n");
	printf("dst ip is ");
	for(int i=0;i<IP_ADDR_LEN;i++){
		if(i)printf(".");
		printf("%d",ipv4->ip_dst[i]);
	}
	printf("\n");
	puts("-------------------------------");
}

void print_tcp_port(libnet_tcp_hdr*tcp){
	puts("-----------TCP Header-----------");
	printf("src port is %u\n",ntohs(tcp->th_sport));
	printf("dst port is %u\n",ntohs(tcp->th_dport));
	puts("--------------------------------");
}

void print_payload(const u_char*packet,int size){
	puts("-----------Payload(Data)-----------");
	printf("Data len is %dbytes\n",size);
	for(int i=0;i<8&&i<size;i++){
		printf("%02x ",packet[i]);
	}
	puts("\n-----------------------------------");
}
