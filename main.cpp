#include <bits/stdc++.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "boyer_moore_search.h"
#include "tcp.h"
using namespace std;

bool isHttp;
int now;
int tcplen,iplen,ethlen;
PEthHdr pethhdr;
PIpHdr piphdr;
PTcpHdr ptcphdr;
string msg="HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

struct Packet{
	EthHdr eth;
	IpHdr ip;
	TcpHdr tcp;
};

void usage() {
	puts("syntax : tcp-block <interface> <pattern>");
	puts("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

Mac get_interface_mac(const string &name) {
	ifstream mac_file("/sys/class/net/" + name + "/address");
	if(!mac_file.is_open()){
		perror("MAC file open error");
		exit(-1);
	}
	string res;
	mac_file>>res;
	return Mac(res);
}

bool find_pattern(const u_char* packet,char* pattern){
	pethhdr = (PEthHdr) packet;
	if(pethhdr->type()!=EthHdr::Ip4) return false;
	piphdr = (PIpHdr)(packet+(ethlen=sizeof(EthHdr)));
	if(piphdr->protocol!=6) return false;
	ptcphdr= (PTcpHdr)(packet+(ethlen+(iplen=((piphdr->h_v&0xf)<<2))));
	// cout<<((iphdr.h_v&0xf)<<2)<<'\n';
	// cout<<"["<<i++<<"]";
	// for(int j=(sizeof(EthHdr)+((iphdr.h_v&0xf)<<2));j<100;j++){
	// 	cout<<packet[j]<<' ';
	// }
	// cout<<'\n';
	// cout<<setw(4)<<hex<<tcphdr.dport()<<'\n';
	if(ptcphdr->dport()==80)isHttp=true;
	else if(ptcphdr->dport()==443)isHttp=false;
	else return false;
	stringstream ss;
	ss<<"recv ["<<setfill('0')<<setw(3)<<now++<<"] : \n";
	for(int j=0;j<piphdr->tlen()-(iplen+(tcplen=(ptcphdr->doff<<2)));j++){
		ss<<packet[j+ethlen+iplen+tcplen];
	}
	ss<<'\n';
	if(boyer_moore_search(
		packet+ethlen+iplen+tcplen,
		piphdr->tlen()-(iplen+tcplen),
		0,pattern,strlen(pattern))!=-1
		//how to find length of pattern if it contains null?
		){
		cout<<ss.str()<<"Found!\n";
		return	true;
	}
	else return false;
}

void block(pcap_t*handle, char*dev, const u_char*packet){
	Mac macadd=get_interface_mac(dev);
	Packet forw,backw;
	forw.eth=backw.eth=*pethhdr;
	forw.ip=backw.ip=*piphdr;
	forw.tcp=backw.tcp=*ptcphdr;
	forw.eth.smac_=backw.eth.smac_=macadd;
	forw.ip.ttl=backw.ip.ttl=128;
	forw.ip.t_len=htons(sizeof(IpHdr)+sizeof(TcpHdr));
	backw.ip.t_len=htons(sizeof(IpHdr)+sizeof(TcpHdr)+isHttp?0:msg.size());
	swap(backw.ip.src,backw.ip.dst);
	swap(backw.tcp.source,backw.tcp.dest);
	forw.tcp.doff=backw.tcp.doff=(sizeof(TcpHdr)>>2);
	forw.tcp.rst=forw.tcp.ack=backw.tcp.ack=1;
	if(isHttp) backw.tcp.fin=1;
	else backw.tcp.rst=1;
	forw.tcp.seq=backw.tcp.ack_seq=htonl(ntohl(ptcphdr->seq)+piphdr->tlen()-(iplen+tcplen));
	backw.tcp.seq=ptcphdr->ack_seq;
	forw.ip.checksum=htons(IpHdr::calcChecksum(&forw.ip));
	backw.ip.checksum=htons(IpHdr::calcChecksum(&backw.ip));
	forw.tcp.check=htons(TcpHdr::calcChecksum(&(forw.ip),&(forw.tcp)));
	backw.tcp.check=htons(TcpHdr::calcChecksum(&(backw.ip),&(backw.tcp)));
	int resf=pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&forw),sizeof(forw));
	int resb=pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&backw),isHttp?sizeof(backw):sizeof(forw));
	if(resf||resb){
		if(resf){
			cout<<"Error with forward\n";
		}
		if(resb){
			cout<<"Error with backward\n";
		}
		exit(-1);
	}
	else{
		cout<<"Blocked!\n";
	}
}

int main(int argc, char* argv[]){
	if (argc != 3) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	string iface=argv[1];
	while (true){
	struct pcap_pkthdr *header;
	const u_char *pkt;
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0){
			continue;
		}
		if (res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
			printf("pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}
		// cout<<"["<<i<<"]";
		// for(int j=0;j<sizeof pkt;j++){
		// 	cout<<pkt[j];
		// }
		// cout<<'\n';
		if(find_pattern(pkt,argv[2])){
			block(handle,dev,pkt);
		}
	}
	pcap_close(handle);
	return 0;
}