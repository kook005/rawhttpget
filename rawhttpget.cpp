/*
 * rawSocket.cpp
 *
 *  Created on: Nov 9, 2014
 *      Author: Xuzhong Feng, Wenbin Zhang
 *
 *  Copyright reserved
 */


#include <arpa/inet.h> //inet_addr
#include <ifaddrs.h> //getifaddres
#include <linux/if_ether.h>
#include <netdb.h> //provides hostent
#include <netinet/in.h>
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <stddef.h>
#include <stdio.h> //for printf
#include <stdlib.h>
#include <string.h> //memset
#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <unistd.h> //close()
#include <ctime> //for timer
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "TcpHeader.h"
#include "TcpPacket.h"

using namespace std;

//main flow
void init(string hostname, string path);
void connect();
void download(string path, string hostname);
void cleanUp();

//helper functions
void getlocalip(char* source_ip, struct sockaddr_in* addr);
int dnsResolve(char* ip, const char* hostname);
unsigned short csum(unsigned short *ptr, int nbytes);
unsigned short calTcpChecksum(struct tcphdr* tcph, char* data);
int recvData(char* buffer);
void delievery(char* datagram, u_int16_t tot_len);
int process_ip_packet(struct iphdr* iph);
void process_http_packet(string data);
int process_packet(char* buffer, int data_size);
unsigned short calTcpChecksumWithOption(struct ip iphdr, struct tcphdr tcphdr,
		uint8_t *options, int opt_len);
void buildHttpRequest(char* datagram, string path, string hostname);
u_int16_t buildTcpPacket(char* datagram, u_int32_t seqNum, u_int32_t ack_seq,
		u_int16_t syn, u_int16_t ack, u_int16_t push, u_int16_t fin);
bool send_ack(TcpPacket tcpPacket);
void sendHttpGet(char* datagram, string path, string hostname);
void urlParse(string& host, string& relative_path, char* input);
void usage();

char source_ip[32];
char des_ip[32];

int portNum;
int sends, rs;
struct sockaddr_in source, dest;

ofstream out_file;

u_int32_t cack;
u_int32_t cseq;
u_int32_t rack;
u_int32_t rseq;

/*
 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
 */
struct pseudo_header {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};


int main(int argc, char** argv) {


	if (argc < 2) {
		usage();
		exit(1);
	}

	string host;
	string relative_path = "/";

	urlParse(host, relative_path, argv[1]);

	init(host, relative_path);
	connect();

	cout << "start download---------------------------\n";
	download(relative_path, host);
	cout << "finish download---------------------------\n";

	cleanUp();
	return 0;
}

/**
 * initialize all parameters needed to download
 * including: send socket, recevied socket, hostname, path, default port
 */
void init(string hostname, string path) {

	//generate a random port which is validable
	srand(time(NULL));
	portNum = rand() + 2000;

	unsigned found = path.find_last_of("/\\");
	string filename = path.substr(found + 1);

	out_file.open(filename.c_str());

	if (out_file == NULL) {
		printf("Unable to create out file.");
	}

	//Create a raw socket to send data
	sends = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (sends == -1) {
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;

	if (setsockopt(sends, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

	int status = dnsResolve(des_ip, hostname.c_str());

	if (status != 0) {
		herror("gethostbyname");
		exit(1);
	}

	//get local ip address
	struct sockaddr_in addr;
	getlocalip(source_ip, &addr);
	addr.sin_family = AF_INET;
	printf("local ip address is %s\n", source_ip);

	source.sin_family = AF_INET;
	source.sin_addr.s_addr = inet_addr(source_ip);

	dest.sin_family = AF_INET;
	dest.sin_port = htons(80);
	dest.sin_addr.s_addr = inet_addr(des_ip);

	//create receive socket
	rs = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (rs == -1) {
		printf("Failed to create socket\n");
		exit(1);
	}

	//initial ack , seq numbers
	cack = 0;
	cseq = 0;
	rack = 0;
	rseq = 0;
}

/**
 * download function:
 * (1) including send httpGet request
 * (2) processing tcp packets from server
 *     all basic funcition implemented:
 *     a. deal with out of order packet, using a buffer to buffer out-order packet
 *     b. ignore duplicate packet, ignore duplicate packets
 *     c. congestion window, follow the algorithm mentioned, adjust window based on received acks and lost acks
 *     d. verify both ip and tcp validaty of recieved packets (mainly in processIpPacket() and processTcpPacket())
 *     e. tear down if no response from server for 3 minutes
 *     f. close socket if fin received
 *     g. retransmit the get request if no acks in one minutes
 */

void download(string path, string hostname) {

	u_int16_t tot_len;

	time_t download_start_time = clock();
	char datagram[4096];

	memset(datagram, 0, 4096);

	//send get request to server, start a timer in case retransmission needed after 1 minute without ack
	time_t get_start_time = clock();
	bool getAcked = false;
	sendHttpGet(datagram, path, hostname);

	int len;
	int status;
	char buffer[2048];

	//congestion window control
	int cwnd = 1;

	//advertised window control
	int wnd = 50000;

	//buffer to Temporarily store the out_order packets
	map<u_int32_t, TcpPacket> buffered_packets;

	//buffer to store received packets to avoid duplicate
	set<int> hash_acks;

	stringstream chunck_data;

	//set the max_duration to 3 minutes
	double max_duration = 3 * 60;

	//recv and process packets from server
	while (true) {

		status = -1;
		memset(buffer, 0, 2048);

		clock_t start = clock();
		clock_t end;

		//1. receive valid packet from server
		while (status == -1) {
			end = clock();
			clock_t duration = (end - start) / (double) CLOCKS_PER_SEC;

			//retransmit get request if no acks after 1 minutes
			if (!getAcked && ((end - get_start_time) / (double) CLOCKS_PER_SEC > 60)) {
				memset(datagram, 0, 4096);
				sendHttpGet(datagram, path, hostname);
			}

			//tear down is no response from server
			if (duration > max_duration) {
				cout
						<< "Didn't get response from server for 3 minutes, tear down";
				cleanUp();
				exit(1);
			}

			memset(buffer, 0, 2048);
			len = recvData(buffer);
			status = process_packet(buffer, len);
		}

		getAcked = true;

		//2. process packet received from server
		TcpPacket packet(buffer, len);

		u_int16_t fin = packet.tcpHeader.fin;

		//tear down the connection if fin is set from the server
		if (fin == 1) {
			chunck_data.seekg(0, ios::end);
			int chunck_length = chunck_data.tellg();

			if (chunck_length > 0) {
				process_http_packet(chunck_data.str());
			}

			time_t download_finish_time = clock();

			cout << "Download finished!" << endl;
			cout << "Total download time is " << ((download_finish_time - download_start_time) / (double) CLOCKS_PER_SEC) << " secs!" << endl;
			memset(datagram, 0, 4096);
			tot_len = buildTcpPacket(datagram, htonl(cseq), htonl(cack + 1), 0,
					1, 0, 1);
			delievery(datagram, tot_len);

			while (status == -1) {
				memset(buffer, 0, 2048);
				len = recvData(buffer);
				status = process_packet(buffer, len);

				if (status == 0) {
					TcpPacket lastOne(buffer, len);
					if (lastOne.tcpHeader.th_ack == cseq + 1) {
						break;
					}
				}
			}

			break;
		}

		if (packet.data_size == 0) {
			continue;
		}

		u_int32_t rseq = packet.tcpHeader.th_seq;

		//duplicate check if find
		if (rseq < cack) {
			if (hash_acks.find(rseq) != hash_acks.end()) {
				cwnd = 1;
			}
			continue;
		}

		buffered_packets.insert(pair<u_int32_t, TcpPacket>(rseq, packet));

		int validNum = 0;

		if (rseq != cack) {

			//if received sequence number is not equal to the one we want, potential lost happened
			memset(datagram, 0, 4096);
			tot_len = buildTcpPacket(datagram, htonl(cseq), htonl(cack), 0, 1,
					0, 0);
			delievery(datagram, tot_len);
			cwnd = 1;

		} else {

			TcpPacket cpacket;

			//Ack received packets, and make sure no. of acked pakcets is less than cwnd
			while (buffered_packets.find(cack) != buffered_packets.end()
					&& validNum < cwnd) {

				cpacket = buffered_packets[cack];
				buffered_packets.erase(cack);

				rseq = cpacket.tcpHeader.th_seq;

				cack = rseq + cpacket.data_size;

				if (cpacket.data_size > 0) {
					chunck_data << cpacket.data;
				}

				hash_acks.insert(rseq);
				validNum++;
				if (cwnd < 1000) {
					cwnd++;
				}
			}

			if (validNum > 0) {
				send_ack(cpacket);
			}

		}
	}
}



/**
 * clear up, close all file descriptor
 */
void cleanUp() {
	close(sends);
	close(rs);
	out_file.close();
}

/**
 * usage: ./rawhttpget http://host/path
 */
void usage(){
	cout << "Usage : ./rawhttpget http://[host]/path" << endl;
}

/**
 * simple function to parse url
 */
void urlParse(string& host, string& relative_path, char* input) {
	char hostname[20];
	char path[30];
	if ((sscanf(input, "http://%[^/]/%s", hostname, path) == 2)) {
		host = hostname;
		relative_path.append(path);
	} else {
		host = hostname;
		relative_path.append("index.html");
	}

	if (hostname == "") {
		usage();
		exit(1);
	}
}


/**
 * send http get to server
 */
void sendHttpGet(char* datagram, string path, string hostname) {
	buildHttpRequest(datagram, path, hostname);
	u_int16_t tot_len = buildTcpPacket(datagram, htonl(cseq), htonl(cack), 0, 1, 1, 0);

	delievery(datagram, tot_len);
}

/**
 * fill in the ip header
 */
u_int16_t buildIpPacket(char* datagram, char* data, int opt_len) {
	struct iphdr* iph = (struct iphdr*) datagram;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data)
			+ opt_len;
	iph->id = htonl(54321); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;      //Set to 0 before calculating checksum
	iph->saddr = source.sin_addr.s_addr;    //Spoof the source ip address
	iph->daddr = dest.sin_addr.s_addr;

	//Ip checksum
	iph->check = csum((unsigned short *) datagram, iph->tot_len);

	return iph->tot_len;
}

/**
 *  fill in the tcp header
 */
u_int16_t buildTcpPacket(char* datagram, u_int32_t seqNum, u_int32_t ack_seq,
		u_int16_t syn, u_int16_t ack, u_int16_t push, u_int16_t fin) {

	struct ip* iph = (struct ip*) datagram;

	//deal with tcp options
	int opt_len;
	uint8_t *options = (uint8_t *) malloc(40 * sizeof(uint8_t));
	memset(options, 0, 40 * sizeof(uint8_t));

	opt_len = 0;

	char* data;
	if (ack_seq == 0) {
		options[0] = 2u;
		opt_len++;  // Option kind 2 = maximum segment size
		options[1] = 4u;
		opt_len++;  // This option kind is 4 bytes long
		uint16_t mss = 1441;
		memcpy((char*) options + 2 * sizeof(uint8_t), &mss, sizeof(uint16_t));
		opt_len++;  // Set maximum segment size to 0x100 = 256
		options[4] = 0x0u;
		opt_len++;
		// Pad to the next 4-byte boundary.
		while ((opt_len % 4) != 0) {
			options[opt_len] = 0;
			opt_len++;
		}
		data = (char*) datagram + sizeof(struct iphdr) + sizeof(struct tcphdr)
				+ opt_len;
	} else {
		data = (char*) datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	}

	u_int16_t len = buildIpPacket(datagram, data, opt_len);

	struct tcphdr* tcph = (struct tcphdr*) (datagram + sizeof(struct ip));

	//TCP Header
	tcph->source = htons(portNum);
	tcph->dest = htons(80);
	tcph->th_seq = seqNum;
	tcph->th_ack = ack_seq;
	tcph->doff = (20 + opt_len) / 4;  //tcp header size
	tcph->fin = fin;
	tcph->syn = syn;
	tcph->rst = 0;
	tcph->psh = push;
	tcph->ack = ack;
	tcph->urg = 0;
	tcph->window = htons(50000); /* maximum allowed window size */
	tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	if (ack_seq == 0) {
		tcph->check = calTcpChecksumWithOption(*iph, *tcph, options, opt_len);
		//set tcp options
		memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), options,
				opt_len * sizeof(uint8_t));
	} else {
		tcph->check = calTcpChecksum(tcph, data);
	}

	free(options);

	return len;
}

/**
 * build Http get request
 */
void buildHttpRequest(char* datagram, string path, string hostname) {
	//Datagram to represent the packet
	char *data = (char*) datagram + sizeof(struct iphdr)
			+ sizeof(struct tcphdr);

	stringstream ss;
	ss << "GET " + path + " HTTP/1.1\r\n" << "Host: " + hostname + "\r\n"
			<< "Connection: keep-alive\r\n\r\n";

	strcpy(data, ss.str().c_str());
}

/**
 * 3 way handshake with server
 */
void connect() {
	cseq = random();
	cack = 0;
	u_int16_t tot_len;

	char datagram[4096];

	memset(datagram, 0, 4096);
	//send syn
	tot_len = buildTcpPacket(datagram, cseq, cack, 1, 0, 0, 0);
	delievery(datagram, tot_len);

	//receive syn and ack from server
	char buffer[2048];
	memset(buffer, 0, 2048);
	int len;
	int status = -1;
	while (status == -1) {
		len = recvData(buffer);
		status = process_packet(buffer, len);
	}

	cseq = rack;
	cack = rseq + 1;

	//send ack back to server
	memset(datagram, 0, 4096);
	tot_len = buildTcpPacket(datagram, htonl(cseq), htonl(cack), 0, 1, 0, 0);

	delievery(datagram, tot_len);
}

/**
 * ack data received from server
 */
bool send_ack(TcpPacket tcpPacket) {

	char datagram[4096];
	int tot_len;

	cseq = tcpPacket.tcpHeader.th_ack;
	cack = tcpPacket.tcpHeader.th_seq + tcpPacket.data_size;

	memset(datagram, 0, 4096);
	tot_len = buildTcpPacket(datagram, htonl(cseq), htonl(cack), 0, 1, 0, 0);
	delievery(datagram, tot_len);
	return false;
}

struct Xgreater {
	bool operator()(const TcpPacket& lx, const TcpPacket& rx) const {
		return lx.tcpHeader.th_seq < rx.tcpHeader.th_seq;
	}
};

/**
 * send data to server
 */
void delievery(char* datagram, u_int16_t tot_len) {
	//Send the packet
	if (sendto(sends, datagram, tot_len, 0, (struct sockaddr *) &dest,
			sizeof(dest)) < 0) {
		printf("send error!");
		cleanUp();
		exit(1);
	}
}

/**
 * recvDatafrom server
 */
int recvData(char* buffer) {
	int len = 0;
	if ((len = recvfrom(rs, buffer, 2048, 0, NULL, NULL)) < 0) {
		printf("receive error");
		exit(1);
	}

	return len;
}

/**
 * Generic checksum calculation function
 */
unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*) &oddbyte) = *(u_char*) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short) ~sum;

	return (answer);
}

/**
 * calculate the tcp checksum for the outgoing packets
 */
unsigned short calTcpChecksum(struct tcphdr* tcph, char* data) {
//Now the TCP checksum
	char* pseudogram;
	struct pseudo_header psh;
	psh.source_address = source.sin_addr.s_addr;
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr)
			+ strlen(data);
	pseudogram = (char *) malloc(psize);

	memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
			sizeof(struct tcphdr) + strlen(data));

	unsigned short result = csum((unsigned short*) pseudogram, psize);

	free(pseudogram);
	return result;
}

//verify tcp checksum from the server
unsigned short verifyTcpChecksum(struct tcphdr* tcph, int data_len) {
//Now the TCP checksum
	char* pseudogram;
	struct pseudo_header psh;
	psh.source_address = dest.sin_addr.s_addr;
	psh.dest_address = source.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(tcph->doff * 4 + data_len);

	int psize = sizeof(struct pseudo_header) + tcph->doff * 4 + data_len;
	pseudogram = (char *) malloc(psize);

	memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
			tcph->doff * 4 + data_len);

	unsigned short result = csum((unsigned short*) pseudogram, psize);

	free(pseudogram);
	return result;
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t calTcpChecksumWithOption(struct ip iphdr, struct tcphdr tcphdr,
		uint8_t *options, int opt_len) {
	uint16_t svalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int chksumlen = 0;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
	ptr += sizeof(iphdr.ip_src.s_addr);
	chksumlen += sizeof(iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
	ptr += sizeof(iphdr.ip_dst.s_addr);
	chksumlen += sizeof(iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0;
	ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
	ptr += sizeof(iphdr.ip_p);
	chksumlen += sizeof(iphdr.ip_p);

	// Copy TCP length to buf (16 bits)
	svalue = htons(sizeof(tcphdr) + opt_len);
	memcpy(ptr, &svalue, sizeof(svalue));
	ptr += sizeof(svalue);
	chksumlen += sizeof(svalue);

	// Copy TCP source port to buf (16 bits)
	memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
	ptr += sizeof(tcphdr.th_sport);
	chksumlen += sizeof(tcphdr.th_sport);

	// Copy TCP destination port to buf (16 bits)
	memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
	ptr += sizeof(tcphdr.th_dport);
	chksumlen += sizeof(tcphdr.th_dport);

	// Copy sequence number to buf (32 bits)
	memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
	ptr += sizeof(tcphdr.th_seq);
	chksumlen += sizeof(tcphdr.th_seq);

	// Copy acknowledgement number to buf (32 bits)
	memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
	ptr += sizeof(tcphdr.th_ack);
	chksumlen += sizeof(tcphdr.th_ack);

	// Copy data offset to buf (4 bits) and
	// copy reserved bits to buf (4 bits)
	cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
	memcpy(ptr, &cvalue, sizeof(cvalue));
	ptr += sizeof(cvalue);
	chksumlen += sizeof(cvalue);

	// Copy TCP flags to buf (8 bits)
	memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
	ptr += sizeof(tcphdr.th_flags);
	chksumlen += sizeof(tcphdr.th_flags);

	// Copy TCP window size to buf (16 bits)
	memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
	ptr += sizeof(tcphdr.th_win);
	chksumlen += sizeof(tcphdr.th_win);

	// Copy TCP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0;
	ptr++;
	*ptr = 0;
	ptr++;
	chksumlen += 2;

	// Copy urgent pointer to buf (16 bits)
	memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
	ptr += sizeof(tcphdr.th_urp);
	chksumlen += sizeof(tcphdr.th_urp);

	// Copy TCP options to buf (variable length, but in 32-bit chunks)
	memcpy(ptr, options, opt_len);
	ptr += opt_len;
	chksumlen += opt_len;

	return csum((uint16_t *) buf, chksumlen);
}

/**
 * loop through all network interface to get valid source ip
 */
void getlocalip(char* source_ip, struct sockaddr_in* addr) {
	struct ifaddrs * ifAddrStruct = NULL;
	struct ifaddrs * ifa = NULL;
	void * tmpAddrPtr = NULL;

	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
			// is a valid IP4 Address
			tmpAddrPtr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
			addr->sin_addr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, source_ip, INET_ADDRSTRLEN);
		}
	}
	if (ifAddrStruct != NULL)
		freeifaddrs(ifAddrStruct);
}

/**
 * dnsReslove to get the ip address of remote server
 */
int dnsResolve(char* ip, const char* hostname) {

	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(hostname)) == NULL) {
		return 1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	int i;
	for (i = 0; addr_list[i] != NULL; i++) {
		strcpy(ip, inet_ntoa(*addr_list[i]));
	}

	printf("%s is %s\n", hostname, ip);

	return 0;
}

// Checksum function
uint16_t checksum(uint16_t *addr, int len) {
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof(uint16_t);
	}

	if (nleft == 1) {
		*(uint8_t *) (&answer) = *(uint8_t *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/*
 *  procssing received ip packets
 *  (1) ip address check
 *  (2) checksum check
 *  (3) protocol and header check
 */

int process_ip_packet(struct iphdr* iph) {

	if (iph->saddr == dest.sin_addr.s_addr
			&& iph->daddr == source.sin_addr.s_addr) {

		//checksum calculate
		u_int16_t cal_check = checksum((unsigned short *) iph, 20);

		if (cal_check != 0) {
			return -1;
		}

		//tcp protocol check
		if (iph->protocol != IPPROTO_TCP) {
			cout << "protocol wrong !" << endl;
			return -1;
		}

		return 0;
	}
	return -1;
}

/*
 *  processing received tcp header
 *  check tcp check sum
 */
int process_tcp_packet(struct tcphdr* tcph, int data_len) {

	u_int16_t r_check = tcph->check;

	// reset tcp checksum to 0
	// build the pseduo header and calculate the checksum
	// compare to the checksum received
	tcph->check = 0;
	u_int16_t cal_check = verifyTcpChecksum(tcph, data_len);

	if (cal_check != r_check) {
		cout << "Error : tcp checksum failed!" << endl;
		return -1;
	}

	return 0;
}

/*
 * write received http data to the file
 */
void process_http_packet(string data) {

	string header = "HTTP/1.1";
	string term = "\r\n\r\n";

	int start = 0;

	if (data.substr(0, header.length()) == header) {
		size_t pos = data.find(term);
		start = pos + 4;
	}

	out_file << data.substr(start);
}

/**
 * filter packets, only process valid packets received from server
 */
int process_packet(char* buffer, int data_size) {

	//process ip header
	struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));

	//validate ip header
	int status = process_ip_packet(iph);

	if (status == 0) {

		struct tcphdr* tcph = (struct tcphdr*) (buffer + sizeof(struct iphdr)
				+ sizeof(struct ethhdr));

		int header_size = iph->ihl * 4 + tcph->doff * 4;
		int data_len = ntohs(iph->tot_len) - header_size;

		//validate tcp header
		status = process_tcp_packet(tcph, data_len);

		if (status != -1) {

			rseq = ntohl(tcph->seq);
			rack = ntohl(tcph->ack_seq);

		}
	}

	return status;
}

