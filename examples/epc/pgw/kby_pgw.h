#include "common.h"
#define MAXCONN 500
#define MAXEVENTS 500

//MTCP SETUP
int done;
mctx_t mctx;
int epollfd;
struct mtcp_epoll_event epevent;

/*----------------------------------------------------------------------------*/
void SignalHandler(int signum)
{
	//Handle ctrl+C here
	mtcp_destroy_context(mctx);	
	mtcp_destroy();
	done = 1;
}
/*----------------------------------------------------------------------------*/

//MTCP Setup done

//sgw data
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

char * dataptr;
unsigned char data[BUF_SIZE];

//pgw specific

string g_sgw_s5_ip_addr = sgw_ip;
string g_pgw_s5_ip_addr = pgw_ip;
string g_pgw_sgi_ip_addr = pgw_ip;
string g_sink_ip_addr = sink_ip;
int sgw_s5_port = sgw_s5_portnum;
int pgw_s5_port = pgw_s5_portnum;
int pgw_sgi_port = pgw_sgi_portnum;
int sink_port = sink_portnum;

class UeContext {
public:
	/* UE id */
	string ip_addr;	

	/* UE location info */
	uint64_t tai; /* Tracking Area Identifier */

	/* EPS session info */
	uint64_t apn_in_use; /* Access Point Name in Use */

	/* EPS bearer info */
	uint8_t eps_bearer_id;
	uint32_t s5_uteid_ul; /* S5 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_uteid_dl; /* S5 Userplane Tunnel Endpoint Identifier - Downlink */
	uint32_t s5_cteid_ul; /* S5 Controlplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_cteid_dl; /* S5 Controlplane Tunnel Endpoint Identifier - Downlink */

	UeContext();
	void init(string, uint64_t, uint64_t, uint8_t, uint32_t, uint32_t, uint32_t, uint32_t);
	~UeContext();
};

UeContext::UeContext() {
	ip_addr = "";
	tai = 0; 
	apn_in_use = 0; 
	s5_uteid_ul = 0; 
	s5_uteid_dl = 0; 
	s5_cteid_ul = 0;
	s5_cteid_dl = 0;
}

void UeContext::init(string arg_ip_addr, uint64_t arg_tai, uint64_t arg_apn_in_use, uint8_t arg_eps_bearer_id, uint32_t arg_s5_uteid_ul, uint32_t arg_s5_uteid_dl, uint32_t arg_s5_cteid_ul, uint32_t arg_s5_cteid_dl) {
	ip_addr = arg_ip_addr;
	tai = arg_tai; 
	apn_in_use = arg_apn_in_use; 
	eps_bearer_id = arg_eps_bearer_id; 
	s5_uteid_ul = arg_s5_uteid_ul; 
	s5_uteid_dl = arg_s5_uteid_dl; 
	s5_cteid_ul = arg_s5_cteid_ul;
	s5_cteid_dl = arg_s5_cteid_dl;
}

UeContext::~UeContext() {

}

pthread_mutex_t s5id_mux; /* Handles s5_id */
pthread_mutex_t sgiid_mux; /* Handles sgi_id */
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



void handle_pgw_accept(int pgw_listen_fd);

void pgw_send_a3(int cur_fd, Packet pkt);