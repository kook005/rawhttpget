/*
 * TcpPacket.h
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#ifndef TCPPACKET_H_
#include "IpHeader.h"
#include "TcpHeader.h"
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<net/ethernet.h>
#include <string>
#include<sstream>
#define TCPPACKET_H_

class TcpPacket {
public:
	TcpPacket(char* datagram, int size);
	TcpPacket();
	virtual ~TcpPacket();

	void buildData(char* data, int size);

	bool operator <(const TcpPacket& other) const {
		return (this->tcpHeader.syn < other.tcpHeader.syn);
	}

	IpHeader ipHeadder;
	TcpHeader tcpHeader;
	std::string data;
	int data_size;
};

#endif /* TCPPACKET_H_ */
