#include "mac.h"
#include "radiotap.h"
#include <string>
#pragma pack(push, 1)
typedef struct BeaconMac{
	uint8_t version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	uint8_t tods:1;
	uint8_t fromds:1;
	uint8_t morefrag:1;
	uint8_t retry:1;
	uint8_t powermgmt:1;
	uint8_t moredata:1;
	uint8_t wep:1;
	uint8_t order:1;
	uint16_t duration;
	Mac da;
	Mac sa;
	Mac bssid;
	uint16_t sequence_control;
}BM;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BeaconFramebodyFixed{
	uint64_t timestamp;
	uint16_t beaconinterval;
	uint16_t capabilityinfo;
}BFF;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BeaconFramebodySSID{
	uint8_t id;
	uint8_t len;
	char essid[32];
}BFS;
#pragma pack(pop)

struct PrintData{
	int beacons;
	std::string essid;
	void addone(){
		this->beacons++;
	}
};

#pragma pack(push, 1)
typedef struct DeauthFrame{
	Radiotap radiotap;
	uint8_t padding[3]={0};
	BM deauth;
	uint16_t reason;
}DF;
#pragma pack(pop)