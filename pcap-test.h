//pcap-test.h
#pragma once
#include<stdint.h>
#include<stdio.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include"libnet.h"

void print_ethernet_mac(libnet_ethernet_hdr*ethernet);
void print_ip(libnet_ipv4_hdr*ipv4);
void print_tcp_port(libnet_tcp_hdr*tcp);
void print_payload(const u_char*packet,int size);