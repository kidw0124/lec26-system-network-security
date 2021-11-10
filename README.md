# 1m-block
## Block table 전처리
![image](https://user-images.githubusercontent.com/38641848/141061592-d6dcaaaa-7759-430c-a553-d5672c7dea41.png)
우선 위와 같이 csv파일에 test.gilgil.net를 추가 했다.
## 
지난주와 같이 iptable을 만든 뒤
![image](https://user-images.githubusercontent.com/38641848/141061942-03499f25-d64b-44ce-84f5-472b238d62e2.png)  
실행한다.
```batch
sudo iptables -A OUTPUT -j NFQUEUE
sudo iptables -A INPUT -j NFQUEUE
```
반대로 끌 때는
```batch
sudo iptables -F
```
설치는
```batch
sudo apt install libnetfilter-queue-dev
```
로 하고 실행은 다음과 같다.
(sudo를 안쓰면 아래와 같은 오류 발생)
```batch
syntax : sudo ./1m-block <site list file>
sample : sudo ./1m-block top-1m.csv
```
![image](https://user-images.githubusercontent.com/38641848/141063598-c4c10aeb-cb6d-4eb9-9242-ce319fc0f4e2.png)

## 실행 결과
![image](https://user-images.githubusercontent.com/38641848/141062695-593996a8-d73f-4621-b112-e11551ffe002.png)
![image](https://user-images.githubusercontent.com/38641848/141062843-dec079b0-39ea-4b7b-a1ab-77a532765b55.png)
실제로 막히며 막았다는 알림이 뜨는 화면이다.
