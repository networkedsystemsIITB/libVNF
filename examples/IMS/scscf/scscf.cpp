#include <libvnf/core.hpp>
#include "packet.h"
#include "common.h"
#include "scscf.h"
#include "utils.h"
#include "security.h"
#include "uecontext.h"
#include "telecom.h"
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
    int act;
    int initial_fd;
    int second_fd;
	uint32_t msui;
    int sipheader;
    int privateidentity;
	uint64_t imsi;
	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t k_asme; /* Key for Access Security Management Entity */
	uint64_t instanceid;
	uint64_t expiration_value ; // 0 in case of deregistration, otherwise non zero
	uint64_t res;
	uint64_t integrity_protected;
	int hss_fd;
	char* status;
};
void handlecase3(int vnfconn_id, void* request, char* packet,int packetlen,int temp){
	Packet pkt;
	char * dataptr; // Pointer to data for copying to packet
	uint64_t imsi;
	int returnval; // Simple address
	int packet_length;
	pkt.clear_pkt();
	bool res; // To store result of HMAC check
	int pcscf_fd; // Stores ran file descriptor
	string status,status1;
	UEcontext current_context; // Stores current UEContext
	mdata *x = static_cast<mdata*>(request);
	pcscf_fd = x->initial_fd;
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
	TRACE(cout<<"I-CSCF->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	x->sipheader = pkt.sip_hdr.msg_type;
	char* pkt1;
	switch(x->sipheader)
	{
		case 1:// Case 1, got authentication challenge from HSS
			pkt.extract_item(x->autn_num);
			pkt.extract_item(x->rand_num);
			pkt.extract_item(x->xres);
			pkt.extract_item(x->k_asme);					
			TRACE(cout<<"Managed to get authorization stuff"<<x->autn_num<<" "<<x->rand_num<<" "<<x->xres<<" "<<x->k_asme<<endl;)
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handlecase3_get);
			break;
		case 2:
			freeReqObj(vnfconn_id, 1);
			closeConn(vnfconn_id);
			pkt.extract_item(status);
			TRACE(cout << "UE status is" << status << endl;)
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
		        sendData(pcscf_fd, pkt1, pkt.len);
			freeReqObj(pcscf_fd, 1);
			closeConn(pcscf_fd);
			break;
		case 3:
			freeReqObj(vnfconn_id, 1);
			closeConn(vnfconn_id);
			pkt.extract_item(current_context.registered);
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
                        sendData(pcscf_fd, pkt1, pkt.len);
			freeReqObj(pcscf_fd, 1);
			closeConn(pcscf_fd);
		break;
	}
}
void handlecase3_get(int vnfconn_id, void* request, void* packet,int packetlen,int temp){
        Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        pkt.clear_pkt();
        bool res; // To store result of HMAC check
        int pcscf_fd; // Stores ran file descriptor
	string send_data;
        mdata *x = static_cast<mdata*>(request);
	pcscf_fd = x->initial_fd;
	freeReqObj(vnfconn_id, 1);
	closeConn(vnfconn_id);
        UEcontext current_context; // Stores current UEContext
	pkt.clear_pkt();
	pkt.append_item(x->imsi); 
	switch(x->sipheader)
	{
		case 1:// Case 1, sending authentication challenge from SCSCF to ICSCF
			memcpy(&current_context, packet, sizeof(UEcontext));
			current_context.autn_num = x->autn_num;
		    current_context.rand_num = x->rand_num;
		    current_context.xres = x->xres;
		    current_context.k_asme = x->k_asme;
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
			pkt.append_item(current_context.autn_num);
			pkt.append_item(current_context.rand_num);
			pkt.append_item(current_context.xres);
			pkt.append_item(current_context.k_asme);
			break;
		case 2:
			
			TRACE(cout << "UE status in send to ICSCF is " << x->status << endl;)
			break;
		case 3:
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
	char* pkt1 = getPktBuf(vnfconn_id);
    memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    sendData(pcscf_fd, pkt1, pkt.len);
	freeReqObj(pcscf_fd, 1);
	closeConn(pcscf_fd);
}
void handleRegistrationRequest(int vnfconn_id, void* request, char* packet,int packetlen,int temp){
	request = allocReqObj(vnfconn_id, 1);
	Packet pkt;
	char * dataptr;
	pkt.clear_pkt();
	int packet_length;
	uint64_t imsi,scscid=1001;
	int returnval;
	bool res; // To store result of HMAC check
	int hss_fd; // File descriptor of ICSCF		
	string send_data;
	UEcontext current_context; // Stores current UEContext	
	mdata *x = static_cast<mdata*>(request);
	hss_fd = createClient(vnfconn_id, SCSCFADDR, HSSADDR, HSSPORTNO, "tcp");
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
    TRACE(cout<<"UE->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	x->imsi = imsi;
    x->sipheader = pkt.sip_hdr.msg_type;
	x->hss_fd = hss_fd;
	switch(x->sipheader)
	{
		case 1:
			current_context.imsi = imsi;
			pkt.extract_item(current_context.instanceid);
			pkt.extract_item(current_context.expiration_value);
			pkt.extract_item(current_context.integrity_protected);
			TRACE(cout<<"ID"<<vnfconn_id<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)
			current_context.gruu = g_telecom.get_gruu(current_context.imsi,current_context.instanceid);
			setData(vnfconn_id, "UEContext", imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
            handleregreq_auth(vnfconn_id, request, packet,packetlen,1);
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

void handleregreq_auth(int vnfconn_id, void* request, void* packet,int packetlen,int temp){
    Packet pkt;
    char * dataptr; // Pointer to data for copying to packet
    uint64_t imsi,scscid=1001;
    int returnval; // Simple address
    int packet_length;
    bool res; // To store result of HMAC check
	string send_data;
	mdata *x = static_cast<mdata*>(request);
    UEcontext current_context; // Stores current UEContext
	x->initial_fd = vnfconn_id;
    pkt.clear_pkt();
    pkt.append_item(x->imsi);
	pkt.append_item(scscid); // Sending scscfid =
	switch(x->sipheader)
	{
		case 1:
			break;
		case 2:
			memcpy(&current_context, packet, sizeof(UEcontext));
            current_context.instanceid = x->instanceid;
            current_context.expiration_value = x->expiration_value;
            current_context.integrity_protected = x->integrity_protected;
			current_context.res = x->res;
            if(current_context.res == current_context.xres)
			{
				TRACE(cout <<imsi << " Authentication successful" << endl;)
				current_context.registered = 1;
			}
			else
			{
				cout <<x->imsi << " Authentication failed" << endl;
				current_context.registered = 0;
			}
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
			pkt.append_item(current_context.registered);
			break;
		case 3:
			memcpy(&current_context, packet, sizeof(UEcontext));
            current_context.instanceid = x->instanceid;
            current_context.expiration_value = x->expiration_value;
            current_context.integrity_protected = x->integrity_protected;
            if(current_context.expiration_value == 0)
			{
				TRACE(cout <<imsi << " Deregistration request started " << endl;)
			}
			else
			{
				cout <<imsi << " Deregistration request failed?" << endl;
			}
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
			pkt.append_item(current_context.instanceid);
			pkt.append_item(current_context.expiration_value);
			pkt.append_item(current_context.integrity_protected);
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
	linkReqObj(x->hss_fd, request);
	registerCallback(x->hss_fd, READ, handlecase3);
	char* pkt1 = getPktBuf(vnfconn_id);
	memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    sendData(x->hss_fd, pkt1, pkt.len);
}

int main(int argc, char *argv[]) {
	vector<int> v;
	initLibvnf(1,128,"127.0.0.1",v,131072,false);
	int serverID = createServer("",SCSCFADDR,SCSCFPORTNO, "tcp");
	registerCallback(serverID, READ, handleRegistrationRequest);
	int reqpool[1] = {sizeof(struct mdata)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;

}
