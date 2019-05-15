#ifndef RAN_H
#define RAN_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <set>
#include <assert.h>
#include <map>
#include "network.h"
#include "packet.h"
#include "sctp_client.h"
#include "security.h"
#include "sync.h"
#include "telecom.h"
#include "utils.h"


class RanContext {
public:
	/* EMM state 
	 * 0 - Deregistered
	 * 1 - Registered 
	 */	
	int emm_state; /* EPS Mobililty Management state */



	/* UE id */
	uint64_t imsi; /* International Mobile Subscriber Identity.  */
	int privateidentity; 
	uint64_t instanceid;
	uint64_t gruu; /* GRUU
	/* Network Operator info */
	uint16_t mcc; /* Mobile Country Code */
	uint16_t mnc; /* Mobile Network Code */
	uint16_t plmn_id; /* Public Land Mobile Network ID */	
	string ip_addr; // Stores IP Address of UE


	uint64_t msisdn; /* Mobile Station International Subscriber Directory Number - Mobile number */

	uint64_t user_server,user_client, pcscf_server,pcscf_client; // Ports in iPSec security Association
	uint64_t spiucpsesp, spiucpsah,spipsucesp, spipsucah; // Security parameter index from PCSCF server- User client
	uint64_t spiuspcesp, spiuspcah,spipcusesp, spipcusah; // Security parameter index from User clienet - PCSCF Server
	
	uint64_t expiration_value ; // 0 in case of deregistration, otherwise non zero

	/* UE security context */
	uint64_t key; /* Primary key used in generating secondary keys */
	uint64_t k_asme; /* Key for Access Security Management Entity */
	uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
	uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
	uint64_t k_nas_int; /* Key for NAS Integrity check */
	uint64_t nas_enc_algo; /* Idenitifier of NAS Encryption / Decryption */
	uint64_t nas_int_algo; /* Idenitifier of NAS Integrity check */
	uint64_t count;
	uint64_t autn_num;
	uint64_t xautn_num;
	uint64_t rand_num;

	uint64_t sqn;
	uint64_t ck;
	uint64_t ik;	
	uint64_t res;	

	uint64_t dir;
	uint64_t pcscf_socket;
	uint64_t expiration_time;

	
	RanContext();
	void init(uint32_t);
	~RanContext();	
};


class Ran {
private:
	SctpClient pcscf_client;
	Packet pkt;

	void set_integrity_crypt_context();
	
public:
	RanContext ran_ctx;
	
	void init(int);
	int conn_pcscf();
	void register1();
	bool authenticate();
	bool set_security();
	bool deregsiter();	

};

#endif /* RAN_H */
