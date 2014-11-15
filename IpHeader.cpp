/*
 * IpHeader.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: kook005
 */

#include "IpHeader.h"

IpHeader::IpHeader() {

}

IpHeader::IpHeader(struct iphdr* iph) {
	// TODO Auto-generated constructor stub
	this->check = iph->check;
	this->daddr = iph->daddr;
	this->frag_off = iph->frag_off;
	this->id = iph->id;
	this->ihl = iph->ihl;
	this->protocol = iph->protocol;
	this->saddr = iph->saddr;
	this->tos = iph->tos;
	this->tot_len = iph->tot_len;
	this->ttl = iph->ttl;
	this->version = iph->version;
}

void IpHeader::buildHeader(struct iphdr* iph) {
	this->check= iph->check;
	this->daddr = iph->daddr;
	this->frag_off = iph->frag_off;
	this->id = iph->id;
	this->ihl= iph->ihl;
	this->protocol= iph->protocol;
	this->saddr= iph->saddr;
	this->tos= iph->tos;
	this->tot_len = iph->tot_len;
	this->ttl = iph->ttl;
	this->version = iph->version;
}

IpHeader::~IpHeader() {
	// TODO Auto-generated destructor stub
}

