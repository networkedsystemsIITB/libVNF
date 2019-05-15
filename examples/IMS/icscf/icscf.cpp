#include <libvnf/core.hpp>
#include "packet.h"
#include "common.h"
#include "icscf.h"
#include "utils.h"
#include "security.h"
#include "uecontext.h"
template<class Archive>
void UEcontext::serialize(Archive &ar, const unsigned int version)
{
	ar & sipheader & emm_state & imsi & privateidentity & instanceid & gruu & expiration_value & key & k_asme & ksi_asme & count & integrity_protected & autn_num & rand_num & xres & res & ck & ik & expiration_time & registered & scscf_addr & scscf_port;


}
UEcontext::UEcontext(){
	sipheader = 0;
        emm_state=0; /* EPS Mobililty Management state */
        /* UE id */
        imsi=0; /* International Mobile Subscriber Identity.  */
        privateidentity=0;
        instanceid=0;
        gruu=0; /* GRUU */
        /* Network Operator info */
        expiration_value=0 ; // 0 in case of deregistration, otherwise non zero
        /* UE security context */
        key=0; /* Primary key used in generating secondary keys */
        k_asme=0; /* Key for Access Security Management Entity */
        ksi_asme=0; /* Key Selection Identifier for Access Security Management Entity */
        count=0;
        integrity_protected=0;

        autn_num=0;
        rand_num=0;
        xres=0;
        res=0;
        ck=0;
        ik=0;
        expiration_time=0;
        registered=0;
        scscf_addr=(char*)""; // Stores IP Address of SCSCF
        scscf_port=0; // SCSCF Port
	
}
UEcontext::~UEcontext(){
}
struct mdata{
	char* scscf_addr; // Stores IP Address of SCSCF
    uint32_t msui;
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
   	int act;
    int initial_fd;
    int second_fd;
    int sipheader;
    int privateidentity;
    int hss_fd;
	int scscf_fd;
};
void handlecase5(int vnfconn_id, void* request, char* packet,int packetlen, int temp){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
    pkt.clear_pkt();
    bool res; // To store result of HMAC check
    int ran_fd; // Stores ran file descriptor
	char* pkt1;
	string status;
	UEcontext current_context; // Stores current UEContext	
        mdata *x = static_cast<mdata*>(request);
        ran_fd = x->initial_fd;
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
        pkt.extract_sip_hdr();
        if (HMAC_ON) { // Check HMACP
        res = g_integrity.hmac_check(pkt, 0);
        if (res == false)
        {
                TRACE(cout << "ransim->pcscf:" << " hmac failure: " << endl;)
                g_utils.handle_type1_error(-1, "hmac failure: ransim->pcscf");
        }
        }
        if (ENC_ON) {
                g_crypt.dec(pkt, 0);
        }
        pkt.extract_item(imsi);
        TRACE(cout<<"I-CSCF->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
        x->sipheader = pkt.sip_hdr.msg_type;
	switch(x->sipheader)
	{
		case 1:
			pkt.extract_item(x->autn_num);
			pkt.extract_item(x->rand_num);
			pkt.extract_item(x->xres);
			pkt.extract_item(x->k_asme);
			TRACE(cout<<"Managed to get authorization stuff"<<x->autn_num<<" "<<x->rand_num<<" "<<x->xres<<" "<<x->k_asme<<endl;)
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handlecase5_get);
			break;
		case 2:
			freeReqObj(vnfconn_id, 1);
			closeConn(vnfconn_id);
			pkt.extract_item(status);
                        TRACE(cout<<imsi<<" is "<<status<<endl;)
                        pkt.clear_pkt();
                        pkt.append_item(imsi);
                        pkt.append_item(status);
                        if (ENC_ON) // Add encryption
                        {
                                g_crypt.enc(pkt,0);
                        }
                        if (HMAC_ON)  // Add HMAC
                        {
                                g_integrity.add_hmac(pkt, 0);
                        }
                        pkt.prepend_sip_hdr(x->sipheader);
                        pkt.prepend_len();
                        pkt1 = getPktBuf(vnfconn_id);
                        memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
                        sendData(ran_fd, pkt1, pkt.len);
			freeReqObj(ran_fd, 1);
			closeConn(ran_fd);
                        TRACE(cout<<" recieved authentication reply from SCSCF "<<endl;)
			break;
		case 3:
			freeReqObj(vnfconn_id, 1);
			closeConn(vnfconn_id);
			pkt.extract_item(current_context.registered);
                        TRACE(cout<<imsi<<" is "<<current_context.registered<<endl;)
			if(current_context.registered == 0)
			{
				delData(vnfconn_id, "UEContext", imsi,LOCAL);
				TRACE(cout<<imsi<<"has been deregistered successfully\n";)
			}
			else
			{
				cout<<"ERROR in deregistration\n";
			}				
                        pkt.clear_pkt();
                        pkt.append_item(imsi);
                        pkt.append_item(current_context.registered);
                        if (ENC_ON) // Add encryption
                        {
                                g_crypt.enc(pkt,0);
                        }
                        if (HMAC_ON)  // Add HMAC
                        {
                                g_integrity.add_hmac(pkt, 0);
                        }
                        pkt.prepend_sip_hdr(x->sipheader);
                        pkt.prepend_len();
                        pkt1 = getPktBuf(vnfconn_id);
                        memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
                        sendData(ran_fd, pkt1, pkt.len);
			freeReqObj(ran_fd, 1);
			closeConn(ran_fd);
                        TRACE(cout<<" recieved authentication reply from SCSCF "<<endl;)
			break;
	}
}
void handlecase5_get(int vnfconn_id, void* request, void* packet,int packetlen, int temp){
	Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
	bool res; // To store result of HMAC check
    int ran_fd; // Stores ran file descriptor
	string send_data;
    mdata *x = static_cast<mdata*>(request);
    ran_fd = x->initial_fd;
	freeReqObj(vnfconn_id, 1);
	closeConn(vnfconn_id);
	UEcontext current_context; // Stores current UEContext
	memcpy(&current_context, packet, sizeof(UEcontext));
	current_context.autn_num = x->autn_num;
	current_context.rand_num = x->rand_num;
	current_context.xres = x->xres;
	current_context.k_asme = x->k_asme;
	setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
	
    pkt.clear_pkt();
    pkt.append_item(x->imsi);
	pkt.append_item(current_context.autn_num);
	pkt.append_item(current_context.rand_num);
	pkt.append_item(current_context.xres);
	pkt.append_item(current_context.k_asme);
	std::string saddr(current_context.scscf_addr);
	pkt.append_item(saddr);
	pkt.append_item(current_context.scscf_port);

	if (ENC_ON) // Add encryption
        {
                g_crypt.enc(pkt,0);
        }
        if (HMAC_ON)  // Add HMAC
        {
                g_integrity.add_hmac(pkt, 0);
        }
        pkt.prepend_sip_hdr(x->sipheader);
        pkt.prepend_len();
		char* pkt1 = getPktBuf(vnfconn_id);
        memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
        sendData(ran_fd, pkt1, pkt.len);
	freeReqObj(ran_fd, 1);
	closeConn(ran_fd);
}

void handlecase3(int vnfconn_id, void* request, char* packet, int packetlen, int temp){
	Packet pkt;
	char * dataptr; // Pointer to data for copying to packet
	uint64_t imsi;
	int returnval; // Simple address
	int packet_length;
	pkt.clear_pkt();
	bool res; // To store result of HMAC check
	int hssStatus; // Whether retrieval of SCSCF is successful
	int scscf_fd;
	scscf_fd = createClient(vnfconn_id, ICSCFADDR, SCSCFADDR, SCSCFPORTNO, "tcp");
	mdata *x = static_cast<mdata*>(request);
	x->scscf_fd = scscf_fd;
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
        pkt.extract_sip_hdr();
	if (HMAC_ON) { // Check HMACP
	res = g_integrity.hmac_check(pkt, 0);
	if (res == false) 
	{
		TRACE(cout << "ransim->pcscf:" << " hmac failure: " << endl;)
		g_utils.handle_type1_error(-1, "hmac failure: ransim->pcscf");
	}		
	} 
	if (ENC_ON) {
		g_crypt.dec(pkt, 0);
	} 	
	pkt.extract_item(imsi);															
	TRACE(cout<<"HSS->ICSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	x->sipheader = pkt.sip_hdr.msg_type;
	string s_add;
	switch(pkt.sip_hdr.msg_type) // Read packet here
	{
		case 1:
		case 2:
		case 3:
			pkt.extract_item(hssStatus);
			pkt.extract_item(s_add);
			pkt.extract_item(x->scscf_port);	
			x->scscf_addr = (char*)s_add.c_str();
			if(hssStatus == 0) cout<<"Get scscf failed ";
			else TRACE(cout<<"Get scscf successful ";)
			TRACE(cout<<"IMSI "<<imsi<<" "<<x->scscf_addr<<" "<<x->scscf_port<<endl;)
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handlecase3_get);
			break;
	}
}
void handlecase3_get(int vnfconn_id, void* request, void* packet,int packetlen, int temp){
	Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi;
    int returnval; // Simple address
    int packet_length;
	string send_data;
    mdata *x = static_cast<mdata*>(request);
	int scscf_fd; // Stores ran file descriptor
	freeReqObj(vnfconn_id, 1);
	closeConn(vnfconn_id);
	UEcontext current_context; // Stores current UEContext
	memcpy(&current_context, packet, sizeof(UEcontext));
    current_context.scscf_addr = x->scscf_addr;
	current_context.scscf_port = x->scscf_port;
	setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
	pkt.clear_pkt();
	pkt.append_item(x->imsi); 
			TRACE(cout<<"Here in case3_get"<<x->sipheader<<endl;)						
	switch(x->sipheader) // Read packet here
	{
		case 1:
			pkt.append_item(current_context.instanceid);
			pkt.append_item(current_context.expiration_value);
			pkt.append_item(current_context.integrity_protected);
			TRACE(cout<<"Before sending"<<current_context.instanceid<<endl;)						
			break;
		case 2:
			pkt.append_item(current_context.instanceid);
            pkt.append_item(current_context.expiration_value);
            pkt.append_item(current_context.integrity_protected);
            TRACE(cout<<"Before sending"<<current_context.instanceid<<endl;)
			pkt.append_item(current_context.res);
			break;
		case 3:
			pkt.append_item(current_context.instanceid);
            pkt.append_item(current_context.expiration_value);
            pkt.append_item(current_context.integrity_protected);
            TRACE(cout<<"Before sending"<<current_context.instanceid<<endl;)
			break;
	}
	if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	} 
	pkt.prepend_sip_hdr(x->sipheader);								
	pkt.prepend_len();
	linkReqObj(x->scscf_fd, request);
    registerCallback(x->scscf_fd, READ, handlecase5);
	char* pkt1 = getPktBuf(vnfconn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    sendData(x->scscf_fd, pkt1, pkt.len);
}
void handleRegistrationRequest(int vnfconn_id, void* request, char* packet,int packetlen,int temp){
	request = allocReqObj(vnfconn_id, 1);
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
	UEcontext current_context; // Stores current UEContext	
	mdata *x = static_cast<mdata*>(request);
	hss_fd = createClient(vnfconn_id, ICSCFADDR, HSSADDR, HSSPORTNO, "tcp");
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
        pkt.extract_sip_hdr();
        if (HMAC_ON) { // Check HMACP
            res = g_integrity.hmac_check(pkt, 0);
            if (res == false)
            {
                TRACE(cout << "ransim->pcscf:" << " hmac failure: " << endl;)
                g_utils.handle_type1_error(-1, "hmac failure: ransim->pcscf");
            }
     	}
        if (ENC_ON) {
            g_crypt.dec(pkt, 0);
        }
    pkt.extract_item(imsi);
	x->imsi = imsi;
	x->initial_fd = vnfconn_id;
	x->hss_fd = hss_fd;
    	x->sipheader = pkt.sip_hdr.msg_type;
	switch(pkt.sip_hdr.msg_type){
		 // Read packet here	
		case 1:
	 		current_context.imsi = imsi;
			pkt.extract_item(current_context.instanceid);
			pkt.extract_item(current_context.expiration_value);
			pkt.extract_item(current_context.integrity_protected);
			TRACE(cout<<"IMSI "<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)
			setData(vnfconn_id, "UEContext", imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
			TRACE(cout<<" value set in setData"<<endl;)
			pkt.clear_pkt();
            pkt.append_item(imsi);
            pkt.append_item(icscid);
	        pkt.append_item(current_context.instanceid);
            pkt.append_item(current_context.expiration_value);
            pkt.append_item(current_context.integrity_protected);
			TRACE(cout<<"UE->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
		        if (ENC_ON) // Add encryption
		        {
		            g_crypt.enc(pkt,0);
		        }
		        if (HMAC_ON)  // Add HMAC
		        {
		            g_integrity.add_hmac(pkt, 0);
		        }
		        pkt.prepend_sip_hdr(x->sipheader);
		        pkt.prepend_len();
				linkReqObj(hss_fd, request);
		        registerCallback(hss_fd, READ, handlecase3);
		        pkt1 = getPktBuf(vnfconn_id);
		        memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
		        sendData(hss_fd, pkt1, pkt.len);
			break;
			case 2:
				pkt.extract_item(x->instanceid);
				pkt.extract_item(x->expiration_value);
				pkt.extract_item(x->integrity_protected);
				pkt.extract_item(x->res);
				getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
				break;
			case 3:
				pkt.extract_item(x->instanceid);
                pkt.extract_item(x->expiration_value);
                pkt.extract_item(x->integrity_protected);
				getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
			break;
	}

}
void handleregreq_auth(int vnfconn_id, void* request, void* packet,int packetlen, int temp){
	Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi,icscid=1000;
        int returnval; // Simple address
        int packet_length;
        bool res; // To store result of HMAC check
        int ran_fd; // Stores ran file descriptor
        string send_data;
        mdata *x = static_cast<mdata*>(request);
        UEcontext current_context; // Stores current UEContext
        memcpy(&current_context, packet, sizeof(UEcontext));
		current_context.instanceid = x->instanceid;
        current_context.expiration_value = x->expiration_value;
        current_context.integrity_protected = x->integrity_protected;
		pkt.clear_pkt();
		pkt.append_item(x->imsi); 
		pkt.append_item(icscid); 
		switch(x->sipheader){
		case 2:
			current_context.res = x->res;
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
			pkt.append_item(current_context.instanceid);
			pkt.append_item(current_context.expiration_value);
			pkt.append_item(current_context.integrity_protected);	
			break;
		case 3:
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
			pkt.append_item(current_context.instanceid);
            pkt.append_item(current_context.expiration_value);
            pkt.append_item(current_context.integrity_protected);
			break;
	}
        TRACE(cout<<"UE->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
        if (ENC_ON) // Add encryption
        {
            g_crypt.enc(pkt,0);
        }
        if (HMAC_ON)  // Add HMAC
        {
            g_integrity.add_hmac(pkt, 0);
        }
        pkt.prepend_sip_hdr(x->sipheader);
        pkt.prepend_len();
	linkReqObj(x->hss_fd, request);
	registerCallback(x->hss_fd, READ, handlecase3);
	char* pkt1 = getPktBuf(vnfconn_id);
	memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
        sendData(x->hss_fd, pkt1, pkt.len);
       
}

int main(int argc, char *argv[]) {
    vector<int> v;
    initLibvnf(1,128,"127.0.0.1",v,131072,false);
	int serverID = createServer("",ICSCFADDR,ICSCFPORTNO, "tcp");
	registerCallback(serverID, READ, handleRegistrationRequest);
	int reqpool[1] = {sizeof(struct mdata)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;

}
