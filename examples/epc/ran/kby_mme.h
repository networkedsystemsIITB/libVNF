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

//MTCP SETUP DONE

//mme data
int read_stream(int conn_fd, uint8_t *buf, int len);

int write_stream(int conn_fd, uint8_t *buf, int len);

struct mdata{
	int act;
	int initial_fd;
	uint8_t buf[500];
	int buflen;
	uint32_t msui;
};

char * dataptr;
unsigned char data[BUF_SIZE];

int maxcores = 10;
//map<int, mdata> fdmap[maxcores];// make it multicore
map<int, mdata> fdmap;


uint64_t ue_count = 0;

	//struct mdata fddata;

//locks
	pthread_mutex_t s1mmeid_mux; /* Handles s1mme_id and ue_count */
	pthread_mutex_t uectx_mux; /* Handles ue_ctx */



//attach 3 regd
string g_trafmon_ip_addr = "10.129.41.57";
string g_mme_ip_addr = mme_ip;
string g_hss_ip_addr = hss_ip;
string g_sgw_s11_ip_addr = sgw_ip;
string g_sgw_s1_ip_addr = sgw_ip;
string g_sgw_s5_ip_addr = sgw_ip;
string g_pgw_s5_ip_addr = pgw_ip;

int g_trafmon_port = 4000;
int g_mme_port = 5000;
int g_hss_port = 6000;
int g_sgw_s11_port = 7000;
int g_sgw_s1_port = 7100;
int g_sgw_s5_port = 7200;
int g_pgw_s5_port = 8000;

uint64_t g_timer = 100;

//
uint32_t gettid(uint64_t guti) {
	uint32_t s11_cteid_mme;
	string tem;

	tem = to_string(guti);
	tem = tem.substr(7, -1); /* Extracting only the last 9 digits of UE MSISDN */
	s11_cteid_mme = stoull(tem);
	return s11_cteid_mme;
}





class UeContext {
public:
	/* EMM state 
	 * 0 - Deregistered
	 * 1 - Registered */
	int emm_state; /* EPS Mobililty Management state */

	/* ECM state 
	 * 0 - Disconnected
	 * 1 - Connected 
	 * 2 - Idle */	 
	int ecm_state; /* EPS Connection Management state */

	/* UE id */
	uint64_t imsi; /* International Mobile Subscriber Identity */
	string ip_addr;
	uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
	uint32_t mme_s1ap_ue_id; /* MME S1AP UE ID */

	/* UE location info */
	uint64_t tai; /* Tracking Area Identifier */
	vector<uint64_t> tai_list; /* Tracking Area Identifier list */
	uint64_t tau_timer; /* Tracking area update timer */

	/* UE security context */
	uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */	
	uint64_t k_asme; /* Key for Access Security Management Entity */	
	uint64_t k_enodeb; /* Key for Access Stratum */	
	uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
	uint64_t k_nas_int; /* Key for NAS Integrity check */
	uint64_t nas_enc_algo; /* Idenitifier of NAS Encryption / Decryption */
	uint64_t nas_int_algo; /* Idenitifier of NAS Integrity check */
	uint64_t count;
	uint64_t bearer;
	uint64_t dir;

	/* EPS info, EPS bearer info */
	uint64_t default_apn; /* Default Access Point Name */
	uint64_t apn_in_use; /* Access Point Name in Use */
	uint8_t eps_bearer_id; /* Evolved Packet System Bearer ID */
	uint8_t e_rab_id; /* Evolved Radio Access Bearer ID */	
	uint32_t s1_uteid_ul; /* S1 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s1_uteid_dl; /* S1 Userplane Tunnel Endpoint Identifier - Downlink */
	uint32_t s5_uteid_ul; /* S5 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_uteid_dl; /* S5 Userplane Tunnel Endpoint Identifier - Downlink */

	/* Authentication info */ 
	uint64_t xres;

	/* UE Operator network info */
	uint16_t nw_type;
	uint16_t nw_capability;

	/* PGW info */
	string pgw_s5_ip_addr;
	int pgw_s5_port;

	/* Control plane info */
	uint32_t s11_cteid_mme; /* S11 Controlplane Tunnel Endpoint Identifier - MME */
	uint32_t s11_cteid_sgw; /* S11 Controlplane Tunnel Endpoint Identifier - SGW */

	UeContext();
	void init(uint64_t, uint32_t, uint32_t, uint64_t, uint16_t);
	~UeContext();
};

class MmeIds {
public:
	uint16_t mcc; /* Mobile Country Code */
	uint16_t mnc; /* Mobile Network Code */
	uint16_t plmn_id; /* Public Land Mobile Network ID */
	uint16_t mmegi; /* MME Group Identifier */
	uint8_t mmec; /* MME Code */
	uint32_t mmei; /* MME Identifier */
	uint64_t gummei; /* Globally Unique MME Identifier */

	MmeIds();
	~MmeIds();
};

void UeContext::init(uint64_t arg_imsi, uint32_t arg_enodeb_s1ap_ue_id, uint32_t arg_mme_s1ap_ue_id, uint64_t arg_tai, uint16_t arg_nw_capability) {
	imsi = arg_imsi;
	enodeb_s1ap_ue_id = arg_enodeb_s1ap_ue_id;
	mme_s1ap_ue_id = arg_mme_s1ap_ue_id;
	tai = arg_tai;
	nw_capability = arg_nw_capability;
}

UeContext::~UeContext() {

}

MmeIds::MmeIds() {
	mcc = 1;
	mnc = 1;
	plmn_id = g_telecom.get_plmn_id(mcc, mnc);
	mmegi = 1;
	mmec = 1;
	mmei = g_telecom.get_mmei(mmegi, mmec);
	gummei = g_telecom.get_gummei(plmn_id, mmei);
}

MmeIds::~MmeIds() {
	
}

UeContext::UeContext() {
	emm_state = 0;
	ecm_state = 0;
	imsi = 0;
	string ip_addr = "";
	enodeb_s1ap_ue_id = 0;
	mme_s1ap_ue_id = 0;
	tai = 0;
	tau_timer = 0;
	ksi_asme = 0;
	k_asme = 0; 
	k_nas_enc = 0; 
	k_nas_int = 0; 
	nas_enc_algo = 0; 
	nas_int_algo = 0; 
	count = 1;
	bearer = 0;
	dir = 1;
	default_apn = 0; 
	apn_in_use = 0; 
	eps_bearer_id = 0; 
	e_rab_id = 0;
	s1_uteid_ul = 0; 
	s1_uteid_dl = 0; 
	s5_uteid_ul = 0; 
	s5_uteid_dl = 0; 
	xres = 0;
	nw_type = 0;
	nw_capability = 0;	
	pgw_s5_ip_addr = "";	
	pgw_s5_port = 0;
	s11_cteid_mme = 0;
	s11_cteid_sgw = 0;	
}


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


//utils.cpp
/*
uint8_t* allocate_uint8_mem(int len) {
	uint8_t *tem;

	if (len <= 0) {
		cout<<"Memory length error: utils_allocateuint8mem"<<endl;
		exit(-1);
	}
	tem = (uint8_t*)malloc(len * sizeof (uint8_t));
	if (tem != NULL) {
		memset(tem, 0, len * sizeof (uint8_t));
		return tem;
	} 
	else {
		cout<<"Memory allocation error: utils_allocateuint8mem"<<endl;
		exit(-1);
	}
}

//security.cpp


void get_hmac(uint8_t *data, int data_len, uint8_t *hmac, uint64_t k_nas_int) {
	HMAC_CTX ctx;
	int res_len;
	uint8_t *key = (uint8_t *)"01234567890123456789012345678901";	
	
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, strlen((const char*)key), EVP_sha1(), NULL);
	HMAC_Update(&ctx, data, data_len);
	HMAC_Final(&ctx, hmac, (unsigned int*)&res_len);
	HMAC_CTX_cleanup(&ctx);	
}

void add_hmac(Packet &pkt, uint64_t k_nas_int) {
	uint8_t *hmac;

	hmac = allocate_uint8_mem(HMAC_LEN);
	get_hmac(pkt.data, pkt.len, hmac, k_nas_int);
	pkt.prepend_item(hmac, HMAC_LEN);
	free(hmac);
}
//	24 jul	fixing thread errors;  

*/		

/*FDMAP
	Value	:	Switch_Case
	1		:	Ran accepted, Data to be read...
	2		:	Data read from RAN and processed, connect to HSS
	3		:	Receive Packet from HSS , Process and send to RAN
	4		:	Sgw reply arrived for attach 3
	5		: 	Sgw Reply for Attach 4
	6		:	detach sgw reply
#compile g++ my_mme.cpp -std=c++11 -o mme.o


	*/



//function definitions
void handle_ran_accept(int ran_listen_fd);

void handle_hss_connect(int cur_fd, Packet pkt, int mme_s1ap_ue_id);

void send_request_hss(int cur_fd, struct mdata fddata);

void send_ran_attach_one(int cur_fd, Packet pkt);

void send_ran_attach_two(int cur_fd, Packet pkt);

void handle_sgw_connect(int cur_fd, Packet pkt, int msui);

void send_request_sgw_athree(int cur_fd, struct mdata fddata);

void send_sgw_afour(int cur_fd, struct mdata fddata, Packet pkt);

void send_sgw_detach(int cur_fd, struct mdata fddata, Packet pkt);
