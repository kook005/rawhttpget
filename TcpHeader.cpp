/*
 * TcpHeader.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#include "TcpHeader.h"

TcpHeader::TcpHeader() {
	source = 0;
	dest = 0;
	doff = 0;
	th_seq = 0;
	th_ack = 0;

	ack = 0;
	syn = 0;
	rst = 0;
	fin = 0;
	psh = 0;
	urg = 0;
	window = 0;
	check = 0;
	urg_ptr = 0;

}

TcpHeader::TcpHeader(struct tcphdr* tcph) {
	// TODO Auto-generated constructor stub
	source = tcph->source;
	dest = tcph->dest;
	doff = tcph->doff;
	th_seq = ntohl(tcph->th_seq);
	th_ack = ntohl(tcph->th_ack);

	ack = tcph->ack;
	syn = tcph->syn;
	rst = tcph->rst;
	psh = tcph->psh;
	fin = tcph->fin;
	urg = tcph->urg;
	window = tcph->window;
	check = tcph->check;
	urg_ptr = tcph->urg_ptr;

}

void TcpHeader::buildHeader(struct tcphdr* tcph) {
	// TODO Auto-generated constructor stub
	source = tcph->source;
	dest = tcph->dest;
	th_seq = ntohl(tcph->th_seq);
	th_ack = ntohl(tcph->th_ack);
	doff = tcph->doff;

	ack = tcph->ack;
	syn = tcph->syn;
	rst = tcph->rst;
	fin = tcph->fin;
	psh = tcph->psh;
	urg = tcph->urg;
	window = tcph->window;
	check = tcph->check;
	urg_ptr = tcph->urg_ptr;

}

TcpHeader::~TcpHeader() {
	// TODO Auto-generated destructor stub
}

