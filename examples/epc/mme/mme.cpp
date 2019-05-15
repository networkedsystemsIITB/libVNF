#include "mme.h"
//#include "uecontext.h"
//template<class Archive>
unordered_map<uint32_t, uint64_t> s1mme_id; /* S1_MME UE identification table: mme_s1ap_ue_id -> guti */
mutex s1mme_lock;

struct mdata{
	char* scscf_addr; // Stores IP Address of SCSCF
	char* session_pkt;
//        uint8_t buf[mdata_BUF_SIZE];
//        int buflen;
//        uint32_t msui;
	//std::string scscf_addr; // Stores IP Address of SCSCF
	uint64_t imsi;
	uint64_t scscf_port; // SCSCF Port
	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t k_asme; /* Key for Access Security Management Entity */
	uint64_t instanceid;
        uint64_t expiration_value ;
        uint64_t res;
        uint64_t integrity_protected;
        int act; //epc
        int initial_fd; //epc
        uint32_t enodeb_s1ap_ue_id;//epc
        uint32_t msui; //epc
	uint32_t s11_cteid_sgw; /* S11 Controlplane Tunnel Endpoint Identifier - SGW */
	char* ue_ip_addr;
	uint32_t s1_uteid_ul; /* S1 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s1_uteid_dl; /* S1 Userplane Tunnel Endpoint Identifier - Downlink */
	uint32_t s5_uteid_ul; /* S5 Userplane Tunnel Endpoint Identifier - Uplink */
	uint32_t s5_uteid_dl; /* S5 Userplane Tunnel Endpoint Identifier - Downlink */
	uint8_t eps_bearer_id; /* Evolved Packet System Bearer ID */
        int second_fd;
        int sipheader;
        int privateidentity;
        int hss_fd; //epc
	int sgw_fd;
	uint64_t guti;
};

void handlecasesession(int conn_id, void* request, char* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr;
    pkt.clear_pkt();
    int packet_length;
    TRACE(cout<<"in session "<<endl;)
    mdata *x = static_cast<mdata*>(request);
    x->session_pkt = (char*)getPktDNE(conn_id, (void*)packet);
    TRACE(cout<<"in session "<<packet_length<<endl;)
    getData(conn_id, "ue_state", x->guti, LOCAL, handlecasesession_get);
}
void handlecasesession_get(int conn_id, void* request, void* packet, int unused1, int unused2){
	Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        string send_data;
        uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
        uint32_t mme_s1ap_ue_id;
        uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
        uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
        uint64_t k_nas_int; /* Key for NAS Integrity check */
	uint8_t eps_bearer_id;
	uint64_t tai;
	uint64_t apn_in_use;
	char* pgw_s5_ip_addr;
	int pgw_s5_port;
//	string saddr;
	uint64_t res;
	uint32_t s11_cteid_mme;
	string tem;
        mdata *x = static_cast<mdata*>(request);
        int sgw_fd; // Stores ran file descriptor
	sgw_fd = createClient(conn_id, mme_ip, sgw_ip, sgw_s11_portnum,"tcp");
	x->sgw_fd = sgw_fd;
        //freeReqObj(conn_id, 1);
        //closeConn(conn_id);
        UeContext current_context; // Stores current UEContext
        //cout<< "in cse3_get "<<packet<<endl;
        memcpy(&current_context, packet, sizeof(UeContext));
	pkt.clear_pkt();
	memmove(&packet_length, (x->session_pkt), sizeof(int)); // Move packet length into packet_len
        if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
        pkt.clear_pkt();
        dataptr = (x->session_pkt)+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
	 TRACE(cout<<"in session_get "<<x->guti<<endl;)
        pkt.data_ptr = 0;
        pkt.len = packet_length;
        pkt.extract_s1ap_hdr();
	k_nas_enc = current_context.k_nas_enc;
	k_nas_int = current_context.k_nas_int;
	if (HMAC_ON) {
		res = g_integrity.hmac_check(pkt, k_nas_int);
		if (res == false) {
				cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << x->guti << endl;
				//cout<<"Error: Hmac failed 3rd attach "<<endl;
				exit(-1);
		}
	}
	if (ENC_ON) {
		g_crypt.dec(pkt, k_nas_enc);
	}
	pkt.extract_item(res);
	if (res == false) {
			cout << "mme_handlesecuritymodecomplete:" << " security mode complete failure: " << x->guti << endl;
			//cout<<"Error: res failed at 3rd attach"<<endl;
			exit(-1);
	}
	else {
			TRACE(cout << "mme_handlesecuritymodecomplete:" << " security mode complete success: " << x->guti << endl;)
			//Success, proceed to UDP
	}
	eps_bearer_id = 5;	//mme.cpp	l:353
							//Locks Here
							//set_pgw_info(guti);
	current_context.pgw_s5_port = g_pgw_s5_port;
	current_context.pgw_s5_ip_addr = g_pgw_s5_ip_addr.c_str();
	//g_sync.mlock(uectx_mux);
	//ue_ctx[guti].s11_cteid_mme = get_s11cteidmme(guti);
	uint64_t guti1 = x->guti;
	tem = to_string(guti1);
	tem = tem.substr(7, -1); /* Extracting only the last 9 digits of UE MSISDN */
	TRACE(cout<<"tem start "<<tem<<endl;)
	s11_cteid_mme = stoull(tem);
	current_context.s11_cteid_mme = s11_cteid_mme;
	current_context.eps_bearer_id = eps_bearer_id;
	//s11_cteid_mme = ue_ctx[guti].s11_cteid_mme;
	imsi = current_context.imsi;
	eps_bearer_id = current_context.eps_bearer_id;
	pgw_s5_ip_addr = current_context.pgw_s5_ip_addr;
	pgw_s5_port = current_context.pgw_s5_port;
	current_context.apn_in_use = 0;	//Added by trishal
	apn_in_use = current_context.apn_in_use;
	tai = current_context.tai;
	setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
	//Packet pkt2;
	TRACE(cout << "s11cteid " << s11_cteid_mme << " "<<x->guti << endl;)
	Packet pkt2;
	pkt2.clear_pkt();
	pkt2.append_item(s11_cteid_mme);
	pkt2.append_item(imsi);
	pkt2.append_item(eps_bearer_id);
	std::string saddr(current_context.pgw_s5_ip_addr);
	pkt2.append_item(saddr); //may
	pkt2.append_item(pgw_s5_port);
	pkt2.append_item(apn_in_use);
	pkt2.append_item(tai);
	pkt2.prepend_gtp_hdr(2, 1, pkt.len, 0);
	pkt2.prepend_len();
	linkReqObj(sgw_fd, request);
        //registerCallback(sgw_fd, READ, handlecase3);
	char* pkt1 = getPktBuf(conn_id);
        memcpy((void*)pkt1, (void*)(pkt2.data), pkt2.len);
        TRACE(cout<<"data sent to SGW"<<x->guti<<endl;)
        registerCallback(x->sgw_fd, READ, handlecasesgwreply1);
//	unsetPktDNE(conn_id, (void*)x->session_pkt);
//        registerCallback(x->initial_fd, READ, handlecaseauth);
        sendData(x->sgw_fd, pkt1, pkt2.len);

}

void handlecasesgwreply1(int conn_id, void* request, char* packet, int unused1, int unused2){
    Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        uint32_t mme_s1ap_ue_id;
    string s_add;
        mdata *x = static_cast<mdata*>(request);
    unsetPktDNE(conn_id, (void*)x->session_pkt);
        pkt.clear_pkt();
        memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
        if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
        pkt.clear_pkt();
        dataptr = packet+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
        //pkt.extract_s1ap_hdr();
    pkt.extract_gtp_hdr();
    pkt.extract_item(x->s11_cteid_sgw);
    TRACE(cout<<"data received from SGW"<<x->guti<<endl;)
    pkt.extract_item(s_add);
    TRACE(cout<<"data received from SGW"<<x->guti<<endl;)
    pkt.extract_item(x->s1_uteid_ul);
    pkt.extract_item(x->s5_uteid_ul);
    pkt.extract_item(x->s5_uteid_dl);
    x->ue_ip_addr = s_add.c_str();
    TRACE(cout<<"data received from SGW"<<x->guti<<endl;)
    if(gettid(x->guti) != x->s11_cteid_sgw)
    {
        cout<<"GUTI not equal A3response"<<x->guti<<" "<<x->s11_cteid_sgw<<endl;
        exit(-1);
    }
    getData(conn_id, "ue_state", x->guti, LOCAL, handlecasesgwreply1_get);
}
void handlecasesgwreply1_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint16_t nw_capability;
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    uint8_t e_rab_id; /* Evolved Radio Access Bearer ID */
    uint64_t k_enodeb; /* Key for Access Stratum */
    vector<uint64_t> tai_list; /* Tracking Area Identifier list */
    uint64_t tau_timer; /* Tracking area update timer */
    bool epsres;
    int tai_list_size;
    uint8_t eps_bearer_id;
    mdata *x = static_cast<mdata*>(request);
    int scscf_fd; // Stores ran file descriptor
    TRACE(cout<<"data received from SGW get"<<x->guti<<endl;)
    //freeReqObj(conn_id, 1);
    //closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    current_context.ip_addr = x->ue_ip_addr;
    current_context.s11_cteid_sgw = x->s11_cteid_sgw;
    current_context.s1_uteid_ul = x->s1_uteid_ul;
    current_context.s5_uteid_ul = x->s5_uteid_ul;
    current_context.s5_uteid_dl = x->s5_uteid_dl;
    tai_list.clear();
    tai_list.push_back(current_context.tai);
    current_context.tau_timer = g_timer;
    current_context.e_rab_id = current_context.eps_bearer_id;
    current_context.k_enodeb = current_context.k_asme;
    e_rab_id = current_context.e_rab_id;
    k_enodeb = current_context.k_enodeb;
    nw_capability = current_context.nw_capability;
    //tai_list = current_context.tai_list;
    tau_timer = current_context.tau_timer;
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    eps_bearer_id = current_context.eps_bearer_id;
    epsres = true;
    tai_list_size = 1;
    setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
    pkt.clear_pkt();
    //pkt.data_ptr = 0;
    pkt.append_item(x->guti);
    pkt.append_item(eps_bearer_id);
    pkt.append_item(e_rab_id);
    pkt.append_item(x->s1_uteid_ul);
    pkt.append_item(k_enodeb);
    pkt.append_item(nw_capability);
    pkt.append_item(tai_list_size);
    pkt.append_item(tai_list);
    pkt.append_item(tau_timer);
    std::string saddr(current_context.ip_addr);
    pkt.append_item(saddr);
    pkt.append_item(g_sgw_s1_ip_addr);
    pkt.append_item(g_sgw_s1_port);
    pkt.append_item(epsres);
    if (ENC_ON) {
        g_crypt.enc(pkt, k_nas_enc);
    }
    if (HMAC_ON) {
        g_integrity.add_hmac(pkt, k_nas_int);
    }
    pkt.prepend_s1ap_hdr(3, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id);
    pkt.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    TRACE(cout<<"session data sent to RAN"<<x->guti<<endl;)
    registerCallback(x->initial_fd, READ, handlecaseeps);
    //registerCallback(x->sgw_fd, READ, handlecasesgwreply1);
    sendData(x->initial_fd, pkt1, pkt.len);
}

void handlecaseeps(int conn_id, void* request, char* packet, int unused1, int unused2){
	Packet pkt;
        char * dataptr;
        pkt.clear_pkt();
        int packet_length;
        TRACE(cout<<"in eps_session "<<endl;)
        mdata *x = static_cast<mdata*>(request);
        x->session_pkt = (char*)getPktDNE(conn_id, (void*)packet);
        TRACE(cout<<"in eps_session "<<packet_length<<endl;)
        getData(conn_id, "ue_state", x->guti, LOCAL, handlecaseeps_get);
}
void handlecaseeps_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
    uint32_t mme_s1ap_ue_id;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    uint8_t eps_bearer_id;
    uint64_t tai;
    uint64_t apn_in_use;
    string pgw_s5_ip_addr;
    uint32_t s11_cteid_sgw; /* S11 Controlplane Tunnel Endpoint Identifier - SGW */
    int pgw_s5_port;
    uint64_t res;
    uint32_t s11_cteid_mme;
    string tem;
    mdata *x = static_cast<mdata*>(request);
    //freeReqObj(conn_id, 1);
    //closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    pkt.clear_pkt();
    memmove(&packet_length, (x->session_pkt), sizeof(int)); // Move packet length into packet_len
    if(packet_length <= 0)
    {
        perror("Error in reading packet_length\n");
        cout<<errno<<endl;
    }
    pkt.clear_pkt();
    dataptr = (x->session_pkt)+sizeof(int);
    memcpy(pkt.data, (dataptr), packet_length);
    TRACE(cout<<"in eps_session_get "<<x->guti<<endl;)
    pkt.data_ptr = 0;
    pkt.len = packet_length;
    pkt.extract_s1ap_hdr();
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    //  g_sync.munlock(uectx_mux);
    if (HMAC_ON) {
        res = g_integrity.hmac_check(pkt, k_nas_int);
        if (res == false) {
            TRACE(cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << x->guti << endl;)
            //cout<<"Error: Hmac failed 3rd attach "<<endl;
            exit(-1);
        }
    }
    if (ENC_ON) {
        g_crypt.dec(pkt, k_nas_enc);
    }
    pkt.extract_item(x->eps_bearer_id);
    pkt.extract_item(x->s1_uteid_dl);
    //g_sync.mlock(uectx_mux);
    current_context.s1_uteid_dl = x->s1_uteid_dl;
    current_context.emm_state = 1;
    setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
    //g_sync.munlock(uectx_mux);
    //TRACE(cout << "mme_handleattachcomplete:" << " attach completed: " << guti << endl;)
    //Locks here
    //g_sync.mlock(uectx_mux);
    x->eps_bearer_id = current_context.eps_bearer_id;
    x->s1_uteid_dl = current_context.s1_uteid_dl;
    s11_cteid_sgw = current_context.s11_cteid_sgw;
    TRACE(cout<<" A4 "<<x->guti<<" s11_cteid_sgw "<<s11_cteid_sgw<<endl;)
    Packet pkt2;
    pkt2.clear_pkt();
    pkt2.append_item(x->eps_bearer_id);
    pkt2.append_item(x->s1_uteid_dl);
    pkt2.append_item(g_trafmon_ip_addr);
    pkt2.append_item(g_trafmon_port);
    pkt2.prepend_gtp_hdr(2, 2, pkt2.len, s11_cteid_sgw);
    pkt2.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt2.data), pkt2.len);
    TRACE(cout<<"EPS data sent to SGW"<<x->guti<<endl;)
    registerCallback(x->sgw_fd, READ, handlecaseeps_sgwreply);
    //unsetPktDNE(conn_id, (void*)x->session_pkt);
//        registerCallback(x->initial_fd, READ, handlecaseauth);
    sendData(x->sgw_fd, pkt1, pkt2.len);
}
void handlecaseeps_sgwreply(int conn_id, void* request, char* packet, int unused1, int unused2){
    Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        uint64_t res;
        uint32_t mme_s1ap_ue_id;
        mdata *x = static_cast<mdata*>(request);
    unsetPktDNE(conn_id, (void*)x->session_pkt);
        pkt.clear_pkt();
        memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
        if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
        pkt.clear_pkt();
        dataptr = packet+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
    pkt.extract_gtp_hdr();
    pkt.extract_item(res);
    if (res == false) {
        cout << "mme_handlemodifybearer:" << " modify bearer failure: " << x->guti << endl;
        exit(-1);
    }
    else{
        getData(conn_id, "ue_state", x->guti, LOCAL, handlecaseeps_sgwreply_get);
    }

}
void handlecaseeps_sgwreply_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    uint16_t nw_capability;
    bool epsres;
    string tem;
    mdata *x = static_cast<mdata*>(request);
    //freeReqObj(conn_id, 1);
    //closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    current_context.ecm_state = 1;
    nw_capability = current_context.nw_capability;
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    epsres = true;
    setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
    pkt.clear_pkt();
    //pkt.data_ptr = 0;
    pkt.append_item(epsres);
    pkt.append_item(x->guti);
    pkt.append_item(nw_capability);
    if (ENC_ON) {
        g_crypt.enc(pkt, k_nas_enc);
    }
    if (HMAC_ON) {
        g_integrity.add_hmac(pkt, k_nas_int);
    }
    pkt.prepend_s1ap_hdr(4, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id);
    //headers not verified at client side...
    pkt.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    TRACE(cout<<"eps data sent to RAN"<<x->guti<<endl;)
    registerCallback(x->initial_fd, READ, handlecasedetach);
    //registerCallback(x->sgw_fd, READ, handlecasesgwreply1);
    sendData(x->initial_fd, pkt1, pkt.len);
}

void handlecasedetach(int conn_id, void* request, char* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr;
    pkt.clear_pkt();
    int packet_length;
    TRACE(cout<<"in detach "<<conn_id<<endl;)
    mdata *x = static_cast<mdata*>(request);
    x->session_pkt = (char*)getPktDNE(conn_id, (void*)packet);
    getData(conn_id, "ue_state", x->guti, LOCAL, handlecasedetach_get);
}
void handlecasedetach_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
    uint32_t mme_s1ap_ue_id;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    uint8_t eps_bearer_id;
    uint64_t tai;
    uint64_t apn_in_use;
    string pgw_s5_ip_addr;
    uint32_t s11_cteid_sgw; /* S11 Controlplane Tunnel Endpoint Identifier - SGW */
    int pgw_s5_port;
    uint64_t res;
    uint32_t s11_cteid_mme;
    uint64_t detach_type;   //  case detach
    mdata *x = static_cast<mdata*>(request);
    //freeReqObj(conn_id, 1);
    //closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    pkt.clear_pkt();
    memmove(&packet_length, (x->session_pkt), sizeof(int)); // Move packet length into packet_len
    if(packet_length <= 0)
    {
        perror("Error in reading packet_length\n");
        cout<<errno<<endl;
    }
    pkt.clear_pkt();
    dataptr = (x->session_pkt)+sizeof(int);
    memcpy(pkt.data, (dataptr), packet_length);
    TRACE(cout<<"in eps_session_get "<<x->guti<<endl;)
    pkt.data_ptr = 0;
    pkt.len = packet_length;
    pkt.extract_s1ap_hdr();
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    eps_bearer_id = current_context.eps_bearer_id;
    tai = current_context.tai;
    s11_cteid_sgw = current_context.s11_cteid_sgw;
    if (HMAC_ON) {
        res = g_integrity.hmac_check(pkt, k_nas_int);
        if (res == false) {
            cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << x->guti << endl;
            //cout<<"Error: Hmac failed 3rd attach "<<endl;
            exit(-1);
        }
    }
    if (ENC_ON) {
        g_crypt.dec(pkt, k_nas_enc);
    }
    pkt.extract_item(x->guti); //Check Same???  mme.cpp-l558
    pkt.extract_item(ksi_asme);
    pkt.extract_item(detach_type);
    pkt.clear_pkt();
    pkt.append_item(eps_bearer_id);
    pkt.append_item(tai);
    pkt.prepend_gtp_hdr(2, 3, pkt.len, s11_cteid_sgw);
    pkt.prepend_len();
    TRACE(cout<<"DETACH PACKT "<<x->guti<<" "<<s11_cteid_sgw<<endl;)
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    registerCallback(x->sgw_fd, READ, handlecasedetach_sgwreply);
    //unsetPktDNE(conn_id, (void*)x->session_pkt);
//        registerCallback(x->initial_fd, READ, handlecaseauth);
    sendData(x->sgw_fd, pkt1, pkt.len);
}

void handlecasedetach_sgwreply(int conn_id, void* request, char* packet, int unused1, int unused2){
	Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        uint64_t res;
        uint32_t mme_s1ap_ue_id;
        mdata *x = static_cast<mdata*>(request);
        unsetPktDNE(conn_id, (void*)x->session_pkt);
        pkt.clear_pkt();
        memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
        if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
        pkt.clear_pkt();
        dataptr = packet+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
        pkt.extract_gtp_hdr();
        pkt.extract_item(res);
        if (res == false) {
                cout << "mme_handlemodifybearer:" << " modify bearer failure: " << x->guti << endl;
                exit(-1);
        }
        else{
                getData(conn_id, "ue_state", x->guti, LOCAL, handlecasedetach_sgwreply_get);
        }

}
void handlecasedetach_sgwreply_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    uint16_t nw_capability;
    uint64_t guti;
    uint32_t mme_s1ap_ue_id; /* MME S1AP UE ID */
    bool epsres;
    string tem;
    mdata *x = static_cast<mdata*>(request);
    mme_s1ap_ue_id = x->msui;
    int ran_fd = x->initial_fd;
    guti = x->guti;
    freeReqObj(conn_id, 1);
    closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    epsres = true;
    pkt.clear_pkt();
    //pkt.data_ptr = 0;
    pkt.append_item(epsres);
    if (ENC_ON) {
        g_crypt.enc(pkt, k_nas_enc);
    }
    if (HMAC_ON) {
        g_integrity.add_hmac(pkt, k_nas_int);
    }
    pkt.prepend_s1ap_hdr(5, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id);
    //headers not verified at client side...
    pkt.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    TRACE(cout<<"detach data sent to RAN"<<x->guti<<endl;)
    s1mme_id.erase(mme_s1ap_ue_id); //lock here
    delData(ran_fd, "ue_state", guti, LOCAL);
    sendData(ran_fd, pkt1, pkt.len);
    freeReqObj(ran_fd, 1);
    closeConn(ran_fd);
}

void handlecaseauth(int conn_id, void* request, char* packet, int unused1, int unused2){
	Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        uint32_t mme_s1ap_ue_id;
        pkt.clear_pkt();
        mdata *x = static_cast<mdata*>(request);
        memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
        if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
        pkt.clear_pkt();
        dataptr = packet+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
	pkt.extract_s1ap_hdr();
	mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
	pkt.extract_item(x->res);
	//cout<<"recieved xres "<<x->res<<endl;
	getData(conn_id, "ue_state", x->guti, LOCAL, handlecaseauth_get);
}
void handlecaseauth_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
    uint32_t mme_s1ap_ue_id;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    uint16_t nw_capability;
    uint64_t nas_enc_algo; /* Idenitifier of NAS Encryption / Decryption */
    uint64_t nas_int_algo; /* Idenitifier of NAS Integrity check */
    uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
    uint64_t k_nas_int; /* Key for NAS Integrity check */
    mdata *x = static_cast<mdata*>(request);
    int scscf_fd; // Stores ran file descriptor
    //freeReqObj(conn_id, 1);
    //closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    TRACE(cout << x->res << " "<<current_context.xres<< " "<<x->guti << endl;)
    if (x->res == current_context.xres)
    {
        TRACE(cout << "mme_handleautn:" << " Authentication successful: " << x->guti << endl;)
    }
    else
    {
        cout<<"mme_handleautn: Failed to authenticate !"<<endl;
        exit(-1);
    }
    current_context.nas_enc_algo = 1;
    current_context.k_nas_enc = current_context.k_asme + current_context.nas_enc_algo + current_context.count + current_context.bearer + current_context.dir;
    //set_integrity_context(guti);
    //Locks here
    current_context.nas_int_algo = 1;
    current_context.k_nas_int = current_context.k_asme + current_context.nas_int_algo + current_context.count + current_context.bearer + current_context.dir;
    ksi_asme = current_context.ksi_asme;
    nw_capability = current_context.nw_capability;
    nas_enc_algo = current_context.nas_enc_algo;
    nas_int_algo = current_context.nas_int_algo;
    k_nas_enc = current_context.k_nas_enc;
    k_nas_int = current_context.k_nas_int;
    pkt.clear_pkt();
    pkt.append_item(ksi_asme);
    pkt.append_item(nw_capability);
    pkt.append_item(nas_enc_algo);
    pkt.append_item(nas_int_algo);

    if (HMAC_ON) {//Check This;;
        g_integrity.add_hmac(pkt, k_nas_int);
        //add_hmac(pkt, k_nas_int);
    }
    //cout<<"Info: Attach 2 done: "<<mme_s1ap_ue_id<<endl;
    pkt.prepend_s1ap_hdr(2, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id);
    pkt.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    TRACE(cout<<"Auth data sent to RAN"<<x->guti<<endl;)
    registerCallback(x->initial_fd, READ, handlecasesession);
//        registerCallback(x->initial_fd, READ, handlecaseauth);
    sendData(x->initial_fd, pkt1, pkt.len);
}

void handlecase3(int conn_id, void* request, char* packet, int unused1, int unused2){
	Packet pkt;
	char * dataptr; // Pointer to data for copying to packet
	uint64_t imsi;
	int returnval; // Simple address
	int packet_length;
	uint32_t mme_s1ap_ue_id;
	pkt.clear_pkt();
	mdata *x = static_cast<mdata*>(request);
	memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
	if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
            cout<<errno<<endl;
        }
	pkt.clear_pkt();
        dataptr = packet+sizeof(int);
	memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
        TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes"<<endl;)
	pkt.extract_diameter_hdr();
	pkt.extract_item(x->autn_num);
	pkt.extract_item(x->rand_num);
	pkt.extract_item(x->xres);
	pkt.extract_item(x->k_asme);
	mme_s1ap_ue_id = x->msui;
	//mlock(s1mmeid_mux);
	s1mme_lock.lock();
	if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
		x->guti = s1mme_id[mme_s1ap_ue_id];
	}
	s1mme_lock.unlock();
	getData(conn_id, "ue_state", x->guti, LOCAL, handlecase3_get);
}
void handlecase3_get(int conn_id, void* request, void* packet, int unused1, int unused2){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    string send_data;
    uint32_t enodeb_s1ap_ue_id; /* eNodeB S1AP UE ID */
    uint32_t mme_s1ap_ue_id;
    uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
    mdata *x = static_cast<mdata*>(request);
    int scscf_fd; // Stores ran file descriptor
    freeReqObj(conn_id, 1);
    closeConn(conn_id);
    UeContext current_context; // Stores current UEContext
    //cout<< "in cse3_get "<<packet<<endl;
    memcpy(&current_context, packet, sizeof(UeContext));
    current_context.xres = x->xres;
    current_context.k_asme = x->k_asme;
    current_context.ksi_asme = 1;
    setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
    ksi_asme = current_context.ksi_asme;
    enodeb_s1ap_ue_id = current_context.enodeb_s1ap_ue_id;
    mme_s1ap_ue_id = x->msui;
    pkt.clear_pkt();
    pkt.append_item(x->autn_num);
    pkt.append_item(x->rand_num);
    pkt.append_item(ksi_asme);
    pkt.prepend_s1ap_hdr(1, pkt.len, enodeb_s1ap_ue_id, mme_s1ap_ue_id);
    pkt.prepend_len();
    char* pkt1 = getPktBuf(conn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    TRACE(cout<<"data sent to RAN"<<x->guti<<endl;)
    registerCallback(x->initial_fd, READ, handlecaseauth);
    sendData(x->initial_fd, pkt1, pkt.len);
}

void handleRegistrationRequest(int conn_id, void* request, char* packet, int unused1, int unused2){
	request = allocReqObj(conn_id, 1);
	Packet pkt;
	char * dataptr;
	pkt.clear_pkt();
	int packet_length;
	uint64_t imsi,icscid=1000;
	int returnval;
	bool res; // To store result of HMAC check
	int hss_fd; // File descriptor of ICSCF
	char* pkt1;
	string send_data="";
	uint64_t num_autn_vectors;
	MmeIds mme_ids;
	uint64_t tai; /* Tracking Area Identifier */
	uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
	uint16_t nw_capability;
	uint32_t mme_s1ap_ue_id;
	uint16_t nw_type;
	UeContext current_context; // Stores current UEContext
	mdata *x = static_cast<mdata*>(request);
	x->act = 1;
	x->initial_fd = conn_id;
	hss_fd = createClient(conn_id, mme_ip, hss_ip, hss_my_port, "tcp");
	memmove(&packet_length, packet, sizeof(int)); // Move packet length into packet_len
    if(packet_length <= 0)
        {
            perror("Error in reading packet_length\n");
    	    cout<<errno<<endl;
        }
		pkt.clear_pkt();
		dataptr = packet+sizeof(int);
        memcpy(pkt.data, (dataptr), packet_length);
        pkt.data_ptr = 0;
        pkt.len = packet_length;
        TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes";)
        pkt.extract_s1ap_hdr();
        if (pkt.s1ap_hdr.mme_s1ap_ue_id == 0) {
        	num_autn_vectors = 1;
        	pkt.extract_item(imsi);
			pkt.extract_item(tai);
			pkt.extract_item(ksi_asme); /* No use in this case */
			pkt.extract_item(nw_capability); /* No use in this case */
			TRACE(cout<<"A1: IMSI from RAN :"<<imsi<<endl;)
			x->enodeb_s1ap_ue_id = pkt.s1ap_hdr.enodeb_s1ap_ue_id;
			x->guti = g_telecom.get_guti(mme_ids.gummei, imsi);
			s1mme_lock.lock();
			ue_count++;
			mme_s1ap_ue_id = ue_count;
			TRACE(cout<<"assigned:"<<mme_s1ap_ue_id<<":"<<ue_count<<endl;)
			s1mme_id[mme_s1ap_ue_id] = x->guti;
			s1mme_lock.unlock();
			current_context.imsi = imsi;
        	current_context.enodeb_s1ap_ue_id = x->enodeb_s1ap_ue_id;
        	current_context.mme_s1ap_ue_id = mme_s1ap_ue_id;
        	current_context.tai = tai;
        	current_context.nw_capability = nw_capability;
        	x->msui = mme_s1ap_ue_id;
        	setData(conn_id, "ue_state", x->guti, LOCAL,  &current_context, sizeof(UeContext), NULL);
        	nw_type = current_context.nw_type;
        	pkt.clear_pkt();
			pkt.append_item(imsi);
			pkt.append_item(mme_ids.plmn_id);
			pkt.append_item(num_autn_vectors);
			pkt.append_item(nw_type);
			pkt.prepend_diameter_hdr(1, pkt.len);
			pkt.prepend_len();
			linkReqObj(hss_fd, request);
            //cout << "before registerCallback" << endl;
            registerCallback(hss_fd, READ, handlecase3);
            //cout << "before getPktBuf" << endl;
            pkt1 = getPktBuf(hss_fd);
            //cout << "before memcpy" << endl;
            memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
            x->act = 3;
            x->hss_fd = hss_fd;
            //cout << "before sendData" << endl;
            //cout << "before sendData" << endl;
            //cout << "before sendData" << endl;
            //cout << "before sendData" << endl;
		    sendData(hss_fd, pkt1, pkt.len);
            //cout << "after all ......" << endl;
        }
}


int main(int argc, char *argv[]) {
    vector<int> dataStorePorts;
    dataStorePorts.push_back(7000);
    dataStorePorts.push_back(7001);
    dataStorePorts.push_back(7002);
    dataStorePorts.push_back(7003);
    initLibvnf(1, 128, "169.254.9.18", dataStorePorts, 131072, false);

	int serverID = createServer("",mme_ip,mme_my_port, "tcp");
	registerCallback(serverID, READ, handleRegistrationRequest);
	int reqpool[1] = {sizeof(struct mdata)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;

}
