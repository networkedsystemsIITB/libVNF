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
#include "defport.h"

#include <map>
#include <unordered_map>
#include <set>

string g_sgw_s11_ip_addr = sgw_ip;
string g_sgw_s1_ip_addr = sgw_ip;
string g_sgw_s5_ip_addr = sgw_ip;
int g_sgw_s11_port = sgw_s11_port ;
int g_sgw_s1_port = sgw_s1_port;
int g_sgw_s5_port = sgw_s5_port;

#define MAXCONN 500
#define MAXEVENTS 500

//MTCP SETUP


int done;
mctx_t mctx;
/*----------------------------------------------------------------------------*/
void SignalHandler(int signum)
{
	//Handle ctrl+C here
	mtcp_destroy_context(mctx);	
	mtcp_destroy();
	done = 1;
}
/*----------------------------------------------------------------------------*/

//generic

int read_stream(int conn_fd, uint8_t *buf, int len);

int write_stream(int conn_fd, uint8_t *buf, int len);

struct mdata{
	int act;
	int initial_fd;
	uint8_t buf[500];
	int buflen;
	uint32_t idfr;//mme copied, may need to modify
};

int maxcores = 10;
//map<int, mdata> fdmap[maxcores];// make it multicore
map<int, mdata> fdmap;

int epollfd;
struct mtcp_epoll_event;

char * dataptr;
unsigned char data[BUF_SIZE];
//sgw specific


class UeContext {
public:
	/* UE location info */
	uint64_t tai; /* Tracking Area Identifier */

	/* EPS session info */
	uint64_t apn_in_use; /* Access Point Name in Use */

	/* EPS Bearer info */
	uint8_t eps_bearer_id; /* Evolved Packet System Bearer Id */
	uint32_t s1_uteid_ul; /* S1 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s1_uteid_dl; /* S1 Userplane Tunnel Endpoint Identifier - Downlink */
	uint32_t s5_uteid_ul; /* S5 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_uteid_dl; /* S5 Userplane Tunnel Endpoint Identifier - Downlink */
	uint32_t s11_cteid_mme; /* S11 Controlplane Tunnel Endpoint Identifier - MME */
	uint32_t s11_cteid_sgw; /* S11 Controlplane Tunnel Endpoint Identifier - SGW */
	uint32_t s5_cteid_ul; /* S5 Controlplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_cteid_dl; /* S5 Controlplane Tunnel Endpoint Identifier - Downlink */

	/* PGW info */
	string pgw_s5_ip_addr;
	int pgw_s5_port;

	/* eNodeB info */
	string enodeb_ip_addr;
	int enodeb_port;

	UeContext();
	void init(uint64_t, uint64_t, uint8_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, string, int);
	~UeContext();
};


UeContext::UeContext() {
	tai = 0; 
	apn_in_use = 0; 
	eps_bearer_id = 0;
	s1_uteid_ul = 0; 
	s1_uteid_dl = 0; 
	s5_uteid_ul = 0; 
	s5_uteid_dl = 0; 
	s11_cteid_mme = 0;
	s11_cteid_sgw = 0;
	s5_cteid_ul = 0;
	s5_cteid_dl = 0;
	pgw_s5_ip_addr = "";
	pgw_s5_port = 0;
	enodeb_ip_addr = "";
	enodeb_port = 0;	
}

void UeContext::init(uint64_t arg_tai, uint64_t arg_apn_in_use, uint8_t arg_eps_bearer_id, uint32_t arg_s1_uteid_ul, uint32_t arg_s5_uteid_dl, uint32_t arg_s11_cteid_mme, uint32_t arg_s11_cteid_sgw, uint32_t arg_s5_cteid_dl, string arg_pgw_s5_ip_addr, int arg_pgw_s5_port) {
	tai = arg_tai; 
	apn_in_use = arg_apn_in_use;
	eps_bearer_id = arg_eps_bearer_id;
	s1_uteid_ul = arg_s1_uteid_ul;
	s5_uteid_dl = arg_s5_uteid_dl;
	s11_cteid_mme = arg_s11_cteid_mme;
	s11_cteid_sgw = arg_s11_cteid_sgw;
	s5_cteid_dl = arg_s5_cteid_dl;
	pgw_s5_ip_addr = arg_pgw_s5_ip_addr;
	pgw_s5_port = arg_pgw_s5_port;
}

UeContext::~UeContext() {

}

//Not needed for single core
	pthread_mutex_t s11id_mux; /* Handles s11_id */
	pthread_mutex_t s1id_mux; /* Handles s1_id */
	pthread_mutex_t s5id_mux; /* Handles s5_id */
	pthread_mutex_t uectx_mux; /* Handles ue_ctx */


void mux_init(pthread_mutex_t &mux) {
	pthread_mutex_init(&mux, NULL);
}

void mlock(pthread_mutex_t &mux) {
	int status;

	status = pthread_mutex_lock(&mux);
	if(status)
	cout<<status<<"Lock error: sync_mlock"<<endl;
}

void munlock(pthread_mutex_t &mux) {
	int status;

	status = pthread_mutex_unlock(&mux);
	if(status)
	cout<<status<<"Unlock error: sync_munlock"<<endl;
}

int make_socket_nb(int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      cout<<"Error: NBS fcntl"<<'\n';
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      cout<<"Error: NBS fcntl flags"<<'\n';
      return -1;
    }

  return 0;
}


