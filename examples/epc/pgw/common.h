#include "diameter.h"
#include "gtp.h"
#include "network.h"
#include "packet.h"
#include "s1ap.h"
#include "sctp_client.h"
#include "sctp_server.h"
#include "security.h"
#include "sync.h"
#include "telecom.h"
#include "udp_client.h"
#include "utils.h"

//temp, mtcp-code. specific
/*#define PORTB 6000
#define CPORTBEG 7000
#define CPORTMAX 7000
#define IPADDRB "169.254.8.254"
#define IPADDRC "192.168.122.170"
#define MAXCON 10000
#define MAXEVENTS 10000
#define THC 10000
#define BPORTBEG 12000
#define BPORTEND 30000
*/
//

#include "defport.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <iterator>
#include <map>
#include <queue>
#include <set>
#include <unordered_map>

#include "cpu.h"
#include "debug.h"
#include "mtcp_api.h"
#include "mtcp_epoll.h"

using namespace std;


//MTCP specific
//#include "../mme_17_july/mtcp_old/mtcp_api.h"


//g++ my_mme.cpp diameter.cpp gtp.cpp network.cpp packet.cpp s1ap.cpp sctp_client.cpp sctp_server.cpp security.cpp sync.cpp telecom.cpp udp_client.cpp utils.cpp -std=c++11 -o mme.o -pthread -lcrypto

uint32_t gettid(uint64_t guti) {
	uint32_t s11_cteid_mme;
	string tem;

	tem = to_string(guti);
	tem = tem.substr(7, -1); /* Extracting only the last 9 digits of UE MSISDN */
	s11_cteid_mme = stoull(tem);
	return s11_cteid_mme;
}

