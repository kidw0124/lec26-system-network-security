#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <sys/socket.h>
#endif // __linux
#ifdef WIN32
#include <winsock2.h>
#include "../mingw_net.h"
#endif // WIN32
#include <iostream>
#include <thread>
#include <bits/stdc++.h>

using namespace std;

#ifdef WIN32
void perror(const char* msg) { fprintf(stderr, "%s %ld\n", msg, GetLastError()); }
#endif // WIN32

void usage() {

	cout << "syntax : echo-server <port> [-e[-b]]\n";
	cout << "  -e : echo\n";
	cout << "  -b : broadcast (only with -e option)\n";
	cout << "sample : echo-server 1234 -e -b\n";
}

set<int>cli_sds;

struct Param {
	bool echo{false}, broadcast{false};
	uint16_t port{0};

	bool parse(int argc, char* argv[]) {
		if(argc < 2){
			return false;
		}
		for (int i = 1; i < argc; i++) {
			string now_arg=argv[i];
			if(now_arg[0]=='-'){
				if(now_arg.find('e')!=string::npos){
					echo=true;
				}
				if(now_arg.find('b')!=string::npos){
					broadcast=true;
				}
			}
			else port = stoi(argv[i]);
		}
		if(broadcast&&!echo){
			return false;
		}
		return port != 0;
	}
} param;

void recvThread(int sd) {
	cout << "connected\n";
	static const int BUFSIZE = 65536;
	char buf[BUFSIZE];
	while (cli_sds.size()>0) {
		ssize_t res = recv(sd, buf, BUFSIZE - 1, 0);
		if (res == 0 || res == -1) {
			cerr << "recv return " << res;
			perror(" ");
			break;
		}
		buf[res] = '\0';
		cout << buf;
		cout.flush();
		if (param.echo) {
			if(param.broadcast){
				for(auto k:cli_sds){
					res = send(k, buf, res, 0);
					if(res == 0 || res == -1){
						cerr << "send return " << res;
						perror(" ");
						cout << "disconnected : "<<k<<"\n";
						close(k);
						cli_sds.erase(k);
					}
				}
			}
			else{
				res = send(sd, buf, res, 0);
				if(res == 0 || res == -1){
					cerr << "send return " << res;
					perror(" ");
					close(sd);
					cout << "disconnected : "<<sd<<"\n";
					cli_sds.erase(sd);
					break;
				}
			}
		}
	}
	close(sd);
}

int main(int argc, char* argv[]) {
	if (!param.parse(argc, argv)) {
		usage();
		return -1;
	}

#ifdef WIN32
	WSAData wsaData;
	WSAStartup(0x0202, &wsaData);
#endif // WIN32

	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		perror("socket");
		return -1;
	}

	int res;
#ifdef __linux__
	int optval = 1;
	res = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (res == -1) {
		perror("setsockopt");
		return -1;
	}
#endif // __linux

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(param.port);

	ssize_t res2 = ::bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (res2 == -1) {
		perror("bind");
		return -1;
	}

	res = listen(sd, 5);
	if (res == -1) {
		perror("listen");
		return -1;
	}

	while (true) {
		struct sockaddr_in cli_addr;
		socklen_t len = sizeof(cli_addr);
		int cli_sd = accept(sd, (struct sockaddr *)&cli_addr, &len);
		if (cli_sd == -1) {
			perror("accept");
			break;
		}
		else cli_sds.insert(cli_sd);
		thread* t = new thread(recvThread, cli_sd);
		t->detach();
	}
	close(sd);
}
