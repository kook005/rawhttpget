/*
 * TcpHeader.h
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#ifndef TCPHEADER_H_
#include<netinet/tcp.h>
#include<arpa/inet.h>
#define TCPHEADER_H_

class TcpHeader {
public:
	TcpHeader(struct tcphdr* tcph);
	TcpHeader();
	virtual ~TcpHeader();

	void buildHeader(struct tcphdr* tcph);

	u_int16_t source;
	u_int16_t dest;
	u_int32_t th_seq;
	u_int32_t th_ack;
	u_int16_t doff;

	u_int16_t ack;
	u_int16_t syn;
	u_int16_t rst;
	u_int16_t psh;
	u_int16_t fin;
	u_int16_t urg;

	u_int16_t window;
	u_int16_t check;

	u_int16_t urg_ptr;

};
#endif /* TCPHEADER_H_ */
