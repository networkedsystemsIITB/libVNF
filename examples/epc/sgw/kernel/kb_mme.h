#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <iostream>
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <iostream>
#include "cpu.h"
#include "debug.h"
#include "netmap_api.h"
#include <limits.h>
//-----	till here from mtcp_server.cpp
//-----	now from common.h
#include <netdb.h>
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

#include <map>
#include <unordered_map>
#include <set>
#include "defport.h"



#define MAX_EVENTS 65536

using namespace std;
int done;
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	//Handle ctrl+C here
	done = 1;
}
/*----------------------------------------------------------------------------*/


