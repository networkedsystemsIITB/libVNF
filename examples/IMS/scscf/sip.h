#ifndef SIP_H
#define SIP_H

#include "utils.h"

class Sip {

public:
	/* 0 - 7 Message Type */
	int msg_type; 
	

	Sip();
	void init(int );
	~Sip();
};

const int SIP_HDR_LEN = sizeof(Sip);

#endif /* SIP_H */