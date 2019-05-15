#include <libvnf/core.hpp>
#include "packet.h"
#include "common.h"
#include "pcscf.h"
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
    int act;
    int initial_fd;
    int second_fd;
	uint32_t msui;
    int sipheader;
    int privateidentity;
	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t k_asme;
	char* scscf_addr; // Stores IP Address of SCSCF
	uint64_t scscf_port;
	uint64_t imsi;
	uint64_t instanceid;
	uint64_t expiration_value ;
	uint64_t res;
	uint64_t integrity_protected;
	int icscf_fd;
};
void handlecase3(int vnfconn_id, void* request, char* packet,int packetlen ,int temp){
	Packet pkt;
	char * dataptr; // Pointer to data for copying to packet
	uint64_t imsi;
	int returnval; // Simple address
	int packet_length;
	pkt.clear_pkt();
	bool res; // To store result of HMAC check
	string status;
	int ran_fd; // Stores ran file descriptor
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
	string s_add;
	char* pkt1;
	x->sipheader = pkt.sip_hdr.msg_type;
	switch(x->sipheader){
		case 1:
			pkt.extract_item(x->autn_num);
			pkt.extract_item(x->rand_num);
			pkt.extract_item(x->xres);
			pkt.extract_item(x->k_asme);
			pkt.extract_item(s_add);
			pkt.extract_item(x->scscf_port);
			x->scscf_addr = (char*)s_add.c_str();
			//x->sipheader = pkt.sip_hdr.msg_type;
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handlecase3_get);
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
			break;
		case 3:
			freeReqObj(vnfconn_id, 1);
			closeConn(vnfconn_id);
			pkt.extract_item(current_context.registered);
			if(current_context.registered == 0)
			{
				TRACE(cout<<imsi<<"has been deregistered successfully\n";)
					delData(vnfconn_id, "UEContext", x->imsi,LOCAL);
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
			break;
	}
}

void handlecase3_get(int vnfconn_id, void* request, void* packet,int packetlen ,int temp){
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
	//TRACE(cout<<"I-CSCF->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	current_context.autn_num = x->autn_num;
	current_context.rand_num = x->rand_num;
	current_context.xres = x->xres;
	current_context.k_asme = x->k_asme;
	current_context.scscf_addr = x->scscf_addr;
	current_context.scscf_port = x->scscf_port;
	current_context.ck = current_context.xres + 2; // Computer ck and Ik
	current_context.ik = current_context.xres + 3;
	setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
	pkt.clear_pkt();
	pkt.append_item(x->imsi); 
	pkt.append_item(current_context.autn_num);
	pkt.append_item(current_context.rand_num);
	pkt.append_item(current_context.k_asme);
	pkt.prepend_sip_hdr(x->sipheader);								
	pkt.prepend_len();
	char* pkt1 = getPktBuf(vnfconn_id);
	memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
    sendData(ran_fd, pkt1, pkt.len);
	freeReqObj(ran_fd, 1);
	closeConn(ran_fd);
}
void handleRegistrationRequest(int vnfconn_id, void* request, char* packet,int packetlen ,int temp){
	request = allocReqObj(vnfconn_id, 1);
	Packet pkt;
	char * dataptr;
	pkt.clear_pkt();
	int packet_length;
	uint64_t imsi;
	int returnval;
	bool res; // To store result of HMAC check
	int icscf_fd; // File descriptor of ICSCF		
	string send_data;
	UEcontext current_context; // Stores current UEContext	
	mdata *x = static_cast<mdata*>(request);
	icscf_fd = createClient(vnfconn_id, PCSCFADDR, ICSCFADDR, ICSCFPORTNO, "tcp");
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
	if(pkt.sip_hdr.msg_type != 1) // Not encrypted in first message of register
	{
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
	}
        pkt.extract_item(imsi);
	x->imsi = imsi;
	x->icscf_fd = icscf_fd;
	int imsi1;
	char* pkt1;
        x->sipheader = pkt.sip_hdr.msg_type;
	x->initial_fd = vnfconn_id;
        TRACE(cout<<"UE->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	switch(pkt.sip_hdr.msg_type) // Read packet here
	{
		case 1:
			current_context.imsi = imsi;
			pkt.extract_item(current_context.instanceid);
			pkt.extract_item(current_context.expiration_value);
			current_context.integrity_protected = 0; // Determining it is not integerity protected
			TRACE(cout<<"registration"<<imsi<<" "<<imsi1<<" "<<current_context.instanceid<<"\t";)
			TRACE(cout<<current_context.expiration_value<<" "<<endl;)
			setData(vnfconn_id, "UEContext", imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
			TRACE(cout<<" value set in setData"<<endl;)
        		pkt.clear_pkt();
		        pkt.append_item(imsi);
			pkt.append_item(current_context.instanceid);
			pkt.append_item(current_context.expiration_value);
			pkt.append_item(current_context.integrity_protected);										
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
			linkReqObj(icscf_fd, request);
			registerCallback(icscf_fd, READ, handlecase3);
			pkt1 = getPktBuf(vnfconn_id);
			memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
			sendData(icscf_fd, pkt1, pkt.len);

			break;
						
		case 2:
			pkt.extract_item(x->instanceid);
			pkt.extract_item(x->expiration_value);
			pkt.extract_item(x->res);
			x->integrity_protected = 1; // Determining it is integerity protected
			TRACE(cout<<" received authentication request from RAN "<<endl;)
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
			break;

		case 3:
			pkt.extract_item(x->instanceid);
                        pkt.extract_item(x->expiration_value);
			TRACE(cout<<" received deregister request from RAN "<<endl;)
			getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
			break;
	}
       

}

void handleregreq_auth(int vnfconn_id, void* request, void* packet,int packetlen ,int temp){
	Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi;
        int returnval; // Simple address
        int packet_length;
        bool res; // To store result of HMAC check
        int ran_fd; // Stores ran file descriptor
        string send_data;
        mdata *x = static_cast<mdata*>(request);
	UEcontext current_context; // Stores current UEContext
    memcpy(&current_context, packet, sizeof(UEcontext));
	pkt.clear_pkt();
	pkt.append_item(x->imsi);
	switch(x->sipheader){
	case 2:
	        //TRACE(cout<<"I-CSCF->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
        	current_context.instanceid = x->instanceid;
	        current_context.expiration_value = x->expiration_value;
        	current_context.res = x->res;
	        current_context.integrity_protected = x->integrity_protected;
			setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);
			pkt.append_item(current_context.instanceid);
			pkt.append_item(current_context.expiration_value);
			pkt.append_item(current_context.integrity_protected);	
			pkt.append_item(current_context.res);
	break;
	case 3:
		current_context.instanceid = x->instanceid;
		current_context.expiration_value = x->expiration_value;
		setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),handleregreq_auth);

		if(current_context.expiration_value == 0)
		{
			TRACE(cout<<"Received de-registration request for IMSI"<<imsi<<endl;)
		}
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
		linkReqObj(x->icscf_fd, request);
        registerCallback(x->icscf_fd, READ, handlecase3);
        char* pkt1 = getPktBuf(vnfconn_id);
        memcpy((void*)pkt1, (void*)(pkt.data), pkt.len);
        sendData(x->icscf_fd, pkt1, pkt.len);

}
int main(int argc, char *argv[]) {
    vector<int> v;
    initLibvnf(1,128,"127.0.0.1",v,131072,false);
    int serverID = createServer("",PCSCFADDR,PCSCFPORTNO, "tcp");
    registerCallback(serverID, READ, handleRegistrationRequest);
    int reqpool[1] = {sizeof(struct mdata)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;

}
