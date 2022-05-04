# deauth-attack
## 802.11 Frame Format
### Frame Format Image
![image](https://user-images.githubusercontent.com/38641848/145157161-851b34e9-e209-46d3-a7a6-879cb28f102a.png)
### MAC header
```cpp
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
```
![image](https://user-images.githubusercontent.com/38641848/145157275-285ab609-92d4-4c77-9699-c1c570cd575f.png)

### Fixed Frame
```cpp
#pragma pack(push, 1)
typedef struct BeaconFramebodyFixed{
	uint64_t timestamp;
	uint16_t beaconinterval;
	uint16_t capabilityinfo;
}BFF;
#pragma pack(pop)
```
![image](https://user-images.githubusercontent.com/38641848/145157438-5d19ceda-5afd-460a-82a7-8f5964ec5c51.png)


### SSID
```cpp
#pragma pack(push, 1)
typedef struct BeaconFramebodySSID{
	uint8_t id;
	uint8_t len;
	char essid[32];
}BFS;
#pragma pack(pop)
```
![image](https://user-images.githubusercontent.com/38641848/145156578-bef93e0a-a703-44bb-833e-cb0010ca919e.png)
