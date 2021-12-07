#include <bits/stdc++.h>
#include <pcap.h>
#include "radiotap.h"
#include "beacon.h"
using namespace std;

map<Mac,PrintData>data;

bool isprint(const string&str){
	for(char k:str){
		if(!isprint(k)){
			return false;
		}
	}
	return true;
}
ostream& operator<<(ostream& os,const Mac&mac){
	return os<<mac;
}

ostream& operator<<(ostream& os,const map<Mac,PrintData>&data){
	os<<setfill('-')<<setw(80)<<"-"<<'\n';
	os<<setfill(' ')<<left<<setw(20)<<"BSSID"<<setw(10)<<"BEACONS"<<setw(40)<<"ESSID"<<'\n';
	for(auto k:data){
		os<<setw(20)<<left<<string(k.first)<<setw(10)<<left<<k.second.beacons<<setw(40)<<left<<k.second.essid<<'\n';
	}
	os<<setfill('-')<<setw(80)<<"-"<<'\n';
	return os;
}

void usage() {
	puts("syntax : airodump <interface>");
	puts("sample : airodump mon0");
}

void airodump(const u_char *pkt){
	Radiotap* radiotap = (Radiotap*)pkt;
	BM* beacon=(BM*)(pkt+radiotap->it_len);
	if(beacon->subtype!=8){
		return;
	}
	Mac bss=beacon->bssid;
	BFF* fixed=(BFF*)(pkt+radiotap->it_len+sizeof(BM));
	BFS* tagged=(BFS*)(pkt+radiotap->it_len+sizeof(BM)+sizeof(BFF));
	string essid(tagged->essid,tagged->len);
	if(data.find(bss)!=data.end()){
		data[bss].addone();
	}
	else{
		if(isprint(essid)){
			data[bss]={1,essid};
		}
		else{
			stringstream ss;
			ss<<"<length : "<<to_string(essid.size())<<">";
			data[bss]={0,ss.str()};
		}
	}
	system("clear");
	cout<<data;
}

int main(int argc, char* argv[]){
	if(argc!=2){
		usage();
		exit(-1);
	}
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	while(true){
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
		airodump(pkt);
	}
	pcap_close(handle);
	return 0;
}