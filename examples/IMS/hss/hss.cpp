// #include "core.hpp"
#include <libvnf/core.hpp>
#include "packet.h"
#include "common.h"
#include "hss.h"
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
	uint64_t instanceid;
	uint64_t expiration_value ;
	uint64_t integrity_protected;
	uint64_t registered;
	uint64_t imsi;
	uint64_t vmid;
	
};
struct hssdata
{
	int key_id,rand_num;
	uint64_t scscfport; // for Sending SCSCF port number
	string scscfaddress;
};
std::map<uint64_t, hssdata> inMemoryDatabase;

void setupkv()
{
	struct hssdata myvar;	
	uint64_t imsi = 119000000000;
	for(imsi = 119000000000; imsi <= 119000000999; imsi++)
	{
		myvar.key_id = imsi%1000;
		myvar.rand_num = myvar.key_id+2;
		inMemoryDatabase[imsi] = myvar;
		inMemoryDatabase[imsi].scscfport =SCSCFPORTNO;
		inMemoryDatabase[imsi].scscfaddress = SCSCFADDR;
	}
}
void handleRegistrationRequest(int vnfconn_id, void* request, char* packet, int packetlen,  int temp){
	request = allocReqObj(vnfconn_id, 1);
	Packet pkt;
	char * dataptr;
	pkt.clear_pkt();
	int packet_length;
	uint64_t imsi,vmid;
	int returnval;
	bool res; // To store result of HMAC check
	string send_data;
        UEcontext current_context; // Stores current UEContext
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
	pkt.extract_item(vmid);
        x->sipheader = pkt.sip_hdr.msg_type;
	x->imsi = imsi;
	x->vmid = vmid;
        TRACE(cout<<"UE->PCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
	switch(vmid)
	{
		case 1000:
			TRACE(cout<<"received"<<vmid<<"from ICSCF\n";)
			switch(pkt.sip_hdr.msg_type)
			{
				case 1: // Case 1, message recieived from ICSCF->HSS for getting address of SCSCF
					current_context.imsi = imsi;
					pkt.extract_item(current_context.instanceid);										
					pkt.extract_item(current_context.expiration_value);										
					pkt.extract_item(current_context.integrity_protected);
					TRACE(cout<<"IMSI "<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)
					setData(vnfconn_id, "UEContext", imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
                	TRACE(cout<<" value set in setData"<<endl;)
					handleregreq_auth(vnfconn_id, request, packet,packetlen,temp);
					break;
				case 2:
					pkt.extract_item(x->instanceid);										
					pkt.extract_item(x->expiration_value);										
					pkt.extract_item(x->integrity_protected);
					getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
					break;
				case 3:
					pkt.extract_item(x->instanceid);
                    pkt.extract_item(x->expiration_value);
                    pkt.extract_item(x->integrity_protected);
					getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
					break;
			}
			break;
		case 1001:
			TRACE(cout<<"received"<<vmid<<"from SCSCF\n";)
			switch(pkt.sip_hdr.msg_type){
				case 1:
					handleregreq_auth(vnfconn_id, request, packet,packetlen,temp);
					break;
				case 2:
					pkt.extract_item(x->registered);
					getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
					break;
				case 3:
					pkt.extract_item(x->instanceid);
                    pkt.extract_item(x->expiration_value);
                    pkt.extract_item(x->integrity_protected);
					getData(vnfconn_id, "UEContext", imsi, LOCAL, handleregreq_auth);
					break;
			}
			break;
	}
}
void handleregreq_auth(int vnfconn_id, void* request, void* packet, int packetlen, int temp){
        Packet pkt;
        char * dataptr; // Pointer to data for copying to packet
        uint64_t imsi,icscid=1000;
        int returnval; // Simple address
        int packet_length;
        bool res; // To store result of HMAC check
        int ran_fd; // Stores ran file descriptor
		int hssStatus;	
		uint64_t scscfport ;//= SCSCFPORTNO; // for Sending SCSCF port number
		string scscfaddress;// = SCSCFADDR; //and address
        string send_data;
		string okay  = "200 OK"; 
		string failed = "500 FAIL";
        mdata *x = static_cast<mdata*>(request);
        UEcontext current_context; // Stores current UEContext
        pkt.clear_pkt();
        pkt.append_item(x->imsi);
		switch(x->vmid)
		{
			case 1000:
			switch(x->sipheader)
			{
				case 1: //Send SCSCF address back to ICSCF
				hssStatus = get_scscf(x->imsi,scscfaddress,scscfport);
                                TRACE(cout<<"IMSI "<<x->imsi<<" hssstatus "<<hssStatus <<"  scscfaddr "<<scscfaddress<<" scscfport "<<scscfport<<endl;)
				pkt.append_item(hssStatus);
				pkt.append_item(scscfaddress);
				pkt.append_item(scscfport);
				break;
				case 2:
				case 3:
					memcpy(&current_context, packet, sizeof(UEcontext));
				    current_context.instanceid = x->instanceid;
				    current_context.expiration_value = x->expiration_value;
        			current_context.integrity_protected = x->integrity_protected;
					setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
					hssStatus = get_scscf(x->imsi,scscfaddress,scscfport);
	                TRACE(cout<<"IMSI "<<x->imsi<<" hssstatus "<<hssStatus <<"  scscfaddr "<<scscfaddress<<" scscfport "<<scscfport<<endl;)
        	        pkt.append_item(hssStatus);
                	pkt.append_item(scscfaddress);
                    pkt.append_item(scscfport);
                    break;
			}					
			break;
		case 1001:
			switch(x->sipheader)
			{
				case 1: // Send Authentication information to SCSCF
				handle_autninfo_req(pkt,x->imsi);
				break;
				case 2:
					memcpy(&current_context, packet, sizeof(UEcontext));
				    current_context.registered = x->registered;
					setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
					if(current_context.registered == 1)
					{
						TRACE(cout<<"Registration successful for imsi "<<x->imsi<<okay<<endl;)
						pkt.append_item(okay);																			
					}							
					else
					{
						cout<<"Registration failed for imsi "<<x->imsi<<endl;
						pkt.append_item(failed);												
					}	
				break;
				case 3:
					memcpy(&current_context, packet, sizeof(UEcontext));
                    current_context.instanceid = x->instanceid;
                    current_context.expiration_value = x->expiration_value;
                    current_context.integrity_protected = x->integrity_protected;
					if(current_context.expiration_value == 0)
					{
						TRACE(cout<<"Deregistration request in progress for"<<imsi<<endl;)
						current_context.registered = 0;
					}								
					else
					{
						cout<<"ERROR in Deregistration for"<<imsi<<endl;
					}
					setData(vnfconn_id, "UEContext", x->imsi, LOCAL,  &current_context, sizeof(UEcontext),NULL);
					pkt.append_item(current_context.registered);
					delData(vnfconn_id, "UEContext", x->imsi, LOCAL);
					if(current_context.registered == 0)
					{
						TRACE(cout<<"Deregistration successful for"<<imsi<<endl;)
					}
					else
					{
						cout<<"ERROR in Deregistration\n";
					}
					break;
			}
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
    sendData(vnfconn_id, pkt1, pkt.len);
	freeReqObj(vnfconn_id, 1);
    closeConn(vnfconn_id);

}

int main(int argc, char *argv[]) {
	setupkv(); // In memory database of 999 Identities.
	vector<int> v;
	initLibvnf(1,128,"127.0.0.1",v,131072,false);
	int serverID = createServer("",HSSADDR,HSSPORTNO, "tcp");
	registerCallback(serverID, READ, handleRegistrationRequest);
	int reqpool[1] = {sizeof(struct mdata)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;

}
int get_scscf(uint64_t imsi,string &scscfaddress,uint64_t &scscfport) 
{
	if(inMemoryDatabase.find(imsi) == inMemoryDatabase.end())
	{
		return 0;	
	}
	else
	{
		scscfaddress = inMemoryDatabase[imsi].scscfaddress;
		scscfport = inMemoryDatabase[imsi].scscfport;		
		return 1;
	}
}
void handle_autninfo_req(Packet &pkt, uint64_t imsi) {
	uint64_t key;
	uint64_t rand_num;
	uint64_t autn_num;
	uint64_t sqn;
	uint64_t xres;
	uint64_t ck;
	uint64_t ik;
	uint64_t k_asme;
	uint64_t num_autn_vectors;
	uint16_t plmn_id;
	uint16_t nw_type;


	get_autn_info(imsi, key, rand_num);
	TRACE(cout << "hss_handleautoinforeq:" << " retrieved from database: " << imsi << endl;)
	sqn = rand_num + 1;
	xres = key + sqn + rand_num;
	autn_num = xres + 1;
	ck = xres + 2;
	ik = xres + 3;
	k_asme = ck + ik + sqn + plmn_id;
	TRACE(cout << "hss_handleautoinforeq:" << " autn:" << autn_num << " rand:" << rand_num << " xres:" << xres << " k_asme:" << k_asme << " " << imsi << endl;)
	pkt.append_item(autn_num);
	pkt.append_item(rand_num);
	pkt.append_item(xres);
	pkt.append_item(k_asme);
	TRACE(cout<<"Managed to send authorization stuff"<<autn_num<<" "<<rand_num<<" "<<xres<<" "<<k_asme<<endl;)
	TRACE(cout << "hss_handleautoinforeq:" << " response sent to scscf: " << imsi << endl;)
}

void get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num) {
	key = inMemoryDatabase[imsi].key_id;
	rand_num = inMemoryDatabase[imsi].rand_num;

}
