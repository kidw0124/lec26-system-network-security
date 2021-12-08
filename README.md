# airodump
## 실행결과
### v2, latest
한글을 isprint함수(printable ascii)에서 받아들이지 못하지만 wchar_t을 쓰면 바이트 수가 변함  
ascii readable을 제외하고는 1만큼 차이가 있음
![image](https://user-images.githubusercontent.com/38641848/145156166-0b676e47-886a-407b-a061-be9d19de2686.png)
![image](https://user-images.githubusercontent.com/38641848/145159145-453060c5-3b48-4130-88f7-cead87ee3fbe.png)



### v1.1
실제와 같다.(beacons는 실행 시간이나 기타 문제로 약간 다른 것도 존재)
![image](https://user-images.githubusercontent.com/38641848/145151173-5d6f687d-d0b4-452f-bc00-43b49d47617c.png)
![image](https://user-images.githubusercontent.com/38641848/145151333-8edf951c-3683-471b-8783-187ec22c7d4c.png)

### v1
실행결과 아래와 같이 나오기는 하지만 업데이트 빈도와 업데이트 횟수가 작았다.(usb3.0관련 문제로 추정)
![image](https://user-images.githubusercontent.com/38641848/145113194-d15088d7-1063-432b-b367-e1b9b9a611d2.png)

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
