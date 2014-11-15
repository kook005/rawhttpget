/*
 * TcpPacket.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#include "TcpPacket.h"

TcpPacket::TcpPacket(char* datagram, int size) {

	// TODO Auto-generated constructor stub
	struct iphdr* iph = (struct iphdr*) (datagram + sizeof(struct ethhdr));

	this->ipHeadder.buildHeader(iph);

	struct tcphdr* tcph = (struct tcphdr*) (datagram + this->ipHeadder.ihl * 4 + sizeof(struct ethhdr));

	this->tcpHeader.buildHeader(tcph);

	int header_size = sizeof(struct ethhdr) + this->ipHeadder.ihl *4 + this->tcpHeader.doff * 4;

	int ip_tcp_header_size = iph->ihl * 4 + tcph->doff * 4;
	int data_len = ntohs(iph->tot_len) - ip_tcp_header_size;

	this->data_size = data_len;

	buildData(datagram + header_size, data_size);
}

TcpPacket::TcpPacket() {

}


void TcpPacket::buildData(char* rawData, int size){
	this->data.clear();
	std::stringstream ss;
	for (int i = 0; i < size; i++) {
		ss << *(rawData + i);
	}

	this->data = ss.str();
}

TcpPacket::~TcpPacket() {
	// TODO Auto-generated destructor stub
}

