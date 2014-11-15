/*
 * IpHeader.h
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#ifndef IPHEADER_H_
#include<netinet/ip.h>
#define IPHEADER_H_

class IpHeader {
public:
	IpHeader(struct iphdr* iph);
	IpHeader();
	virtual ~IpHeader();

	void buildHeader(struct iphdr* iph);

    u_int16_t tot_len;
	unsigned int version;
	u_int8_t tos;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t daddr;
	u_int32_t saddr;
	unsigned int ihl;

};

#endif /* IPHEADER_H_ */
