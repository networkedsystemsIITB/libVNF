#ifndef PACKET_H
#define PACKET_H

/* (C) ip_hdr */
#include <netinet/ip.h>

#include "utils.h"
#include "sip.h"

#define BUF_SIZE 1024
#define IP_HDR_LEN 20
#define DATA_SIZE 800

class Packet {
public:
	Sip sip_hdr;
	uint8_t *data;
	int data_ptr;
	int len;
	
	Packet();
	Packet(const Packet&);
	friend void swap(Packet&, Packet&);
	Packet& operator=(Packet);
	Packet(Packet&&);
	void append_item(bool);
	void append_item(int);
	void append_item(uint8_t);
	void append_item(uint16_t);
	void append_item(uint32_t);
	void append_item(uint64_t);
	void append_item(vector<uint64_t>);
	void append_item(uint8_t*, int);	
	void append_item(const char*);	
	void append_item(string);
	void prepend_item(uint8_t*, int);
	void prepend_sip_hdr(int);
	void prepend_len();
	void extract_item(bool&);
	void extract_item(int&);
	void extract_item(uint8_t&);
	void extract_item(uint16_t&);
	void extract_item(uint32_t&);
	void extract_item(uint64_t&);
	void extract_item(vector<uint64_t>&, int);
	void extract_item(uint8_t*, int);	
	void extract_item(char*, int);	
	void extract_item(string&);
	void extract_sip_hdr();
	
	void truncate();
	void clear_pkt();
	struct ip* allocate_ip_hdr_mem(int);
	~Packet();
};

#endif /* PACKET_H */
