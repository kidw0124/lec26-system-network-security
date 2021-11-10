#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <queue>

#include "libnet.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

string host_file;
const int domain_char_size=10+26+2;
int MAX_DOMAIN_SIZE=0;

int get_key(const char&k){
	///domain rules (except kor) in http://ktword.co.kr/test/view/view.php?m_temp1=385
	if('0'<=k&&k<='9'){
		return k-'0';
	}
	else if('A'<=k&&k<='Z'){
		return k-'A'+10;
	}
	else if('a'<=k&&k<='z'){
		return k-'a'+10;
	}
	else if(k=='.'){
		return 10+26;
	}
	else if(k=='-'){
		return 10+26+1;
	}
	else{
		return -1;
	}
}

class Trie{
private:
	vector<Trie*>children;
	Trie*fail;
	bool is_end;
	string host_name;
public:
	Trie(){
		this->children.resize(domain_char_size,NULL);
		this->fail=NULL;
		this->is_end=false;
		this->host_name="";
	}
	~Trie(){
		for(int i=0;i<domain_char_size;i++){
			if(children[i]){
				delete children[i];
			}
		}
	}
	Trie*get_fail(){
		return this->fail;
	}
	void set_fail(Trie*fail){
		this->fail=fail;
	}
	Trie*get_children(int i){
		return this->children[i];
	}
	bool get_is_end(){
		return this->is_end;
	}
	void set_is_end(bool is_end){
		this->is_end=is_end;
	}
	string get_host_name(){
		return this->host_name;
	}
	void set_host_name(string host_name){
		this->host_name=host_name;
	}
	void insert(const string&key, int ind){
		int nkey=get_key(key[ind]);
		if(nkey==-1){
			fprintf(stderr, "Invalid domaind name!\n");
			exit(1);
		}
		if(key.size()<ind){
			if(!children[nkey]){
				children[nkey]=new Trie;
			}
			children[nkey]->insert(key,ind+1);
		}
		else{
			is_end=true;
			host_name=key;
		}
	}
};

Trie*root;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		/*printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);*/
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);*/
	}

	// mark = nfq_get_nfmark(tb);
	// if (mark)
	// 	printf("mark=%u ", mark);

	// ifi = nfq_get_indev(tb);
	// if (ifi)
	// 	printf("indev=%u ", ifi);

	// ifi = nfq_get_outdev(tb);
	// if (ifi)
	// 	printf("outdev=%u ", ifi);
	// ifi = nfq_get_physindev(tb);
	// if (ifi)
	// 	printf("physindev=%u ", ifi);

	// ifi = nfq_get_physoutdev(tb);
	// if (ifi)
	// 	printf("physoutdev=%u ", ifi);

	// ret = nfq_get_payload(tb, &data);
	// if (ret >= 0)
	// 	printf("payload_len=%d\n", ret);

	// fputc('\n', stdout);

	return id;
}

bool check_http_methods(const string&httpdata){
	std::vector<string> methods({"GET","POST","PUT","HEAD","DELETE","CONNECT","OPTIONS","TRACE","PATCH"});
	for(string k:methods){
		if(httpdata.find(k)!=string::npos){
			return true;
		}
	}
	return false;
}

string check_blocked_site(const string&httpdata){
	string hostdata=httpdata.substr(httpdata.find("Host: ")+6);
	if(hostdata.find("www.")!=string::npos){
		hostdata=hostdata.substr(hostdata.find("www.")+4,MAX_DOMAIN_SIZE);
	}
	else hostdata=hostdata.substr(0,MAX_DOMAIN_SIZE);
	Trie*now=root;
	for(char k:hostdata){
		int next=get_key(k);
		if(next==-1){
			fprintf(stderr, "Invalid domaind name!\n");
			exit(1);
		}
		while(now!=root&&!(now->get_children(next))){
			now=now->get_children(next);
		}
		if(now->get_is_end()){
			return now->get_host_name();
		}
	}
	return "";
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	static int ord=0;
	ord++;
	printf("[%d] ",ord);
	u_int32_t id = print_pkt(nfa);
	// printf("entering callback\n");
	u_char*pkt;
	int len=nfq_get_payload(nfa, &pkt);
	if(len>=0){
		int nowlen=0;
		struct libnet_ipv4_hdr*ip=(struct libnet_ipv4_hdr*)pkt;
		if((ip->ip_p) != 0x06){
			printf("No tcp(ip->p : %02x)\n",ip->ip_p);
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
		nowlen+=ip->ip_hl * 4;
		struct libnet_tcp_hdr*tcp=(struct libnet_tcp_hdr*)(pkt+nowlen);
		nowlen+=tcp->th_off * 4;
		if(ntohs(tcp->th_sport)!=80&&ntohs(tcp->th_dport)!=80){
			printf("No http(sport : %d, dport : %d)\n",tcp->th_sport,tcp->th_dport);
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
		string httpdata=(char*)(pkt+nowlen);
		string this_host;
		if(httpdata.size()>0&&
				(check_http_methods(httpdata))
				/// header methods in https://developer.mozilla.org/ko/docs/Web/HTTP/Methods
			){
			if((this_host=check_blocked_site(httpdata))!=""){
				printf("Blocked %s!\n",this_host.c_str());
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
			else{
				printf("No %s!\n",this_host.c_str());
				return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			}
		}
		else{
			puts("No http(method wrong)");
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
	}
	else{
		puts("len=0");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

void usage(){
	puts("syntax : sudo ./1m-block <site list file>\nsample : sudo ./1m-block top-1m.csv");
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc!=2){
		usage();
		exit(1);
	}
	host_file=argv[1];
	root=new Trie;
	fstream block_list;
	block_list.open(host_file,ios::in);
	if(block_list.fail()){
		perror("Error in opening file");
		exit(1);
	}
	while(block_list.peek()!=EOF){
		string block_host;
		getline(block_list,block_host);
		if(block_host.find('\r')!=string::npos){
			block_host=block_host.substr(0,block_host.find('\r'));
		}
		if(block_host.find('\n')!=string::npos){
			block_host=block_host.substr(0,block_host.find('\n'));
		}
		if(block_host.find(',')==string::npos){
			continue;
		}
		else{
			MAX_DOMAIN_SIZE=max(MAX_DOMAIN_SIZE,(int)block_host.size());
			root->insert(block_host.substr(block_host.find(',')+1),0);
		}
	}
	MAX_DOMAIN_SIZE+=10;

	queue<Trie*>que;
	root->set_fail(root);
	que.push(root);
	while(!que.empty()){
		Trie*now=que.front();
		que.pop();
		for(int i=0;i<domain_char_size;i++){
			Trie*next=now->get_children(i);
			if(!next){
				continue;
			}
			else{
				Trie*anc=now->get_fail();
				while(anc!=root&&!(anc->get_children(i))){
					anc=anc->get_fail();
				}
				if(now!=root&&anc->get_children(i)){
					anc=anc->get_children(i);
				}
				next->set_fail(anc);
				if(next->get_fail()->get_is_end()){
					next->set_is_end(true);
					next->set_host_name(next->get_fail()->get_host_name());
				}
				que.push(next);
			}
		}
	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
