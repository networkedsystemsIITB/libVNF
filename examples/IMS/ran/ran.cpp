#include "ran.h"
#include "common.h"

RanContext::RanContext() {
	emm_state = 0; 
	imsi = 0; 
	gruu = 0; 
	ip_addr = UEADDR;
	instanceid = 1;

	key = 0; 
	k_asme = 0; 
	ksi_asme = 7; 
	k_nas_enc = 0; 
	k_nas_int = 0; 
	nas_enc_algo = 0; 
	nas_int_algo = 0; 

	user_server = 0;
	user_client = 0;
	pcscf_server = PCSCFPORTNO;
	pcscf_client= 0;

	expiration_time = 1;

	mcc = 1; 
	mnc = 1; 
	plmn_id = g_telecom.get_plmn_id(mcc, mnc);
	msisdn = 0; 
}

void RanContext::init(uint32_t arg) {
	privateidentity =(int) arg;
	key = arg;
	msisdn = 9000000000 + arg;
	imsi = g_telecom.get_imsi(plmn_id, msisdn);
	expiration_value = 1;
	user_server = 6000 + arg;
}
RanContext::~RanContext() {

}

void Ran::init(int arg) {
	ran_ctx.init(arg);
}

int Ran::conn_pcscf() {
	pcscf_client.conn(PCSCFADDR,PCSCFPORTNO);
}
void Ran::register1() {
	uint64_t imsi;
	bool res;

	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	pkt.append_item(ran_ctx.expiration_value);
	TRACE(cout<<ran_ctx.instanceid<<" "<<ran_ctx.expiration_value<<endl;)
	imsi = ran_ctx.imsi;

	/*if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	}  */	
	TRACE(cout<<"Registration process for "<<ran_ctx.imsi <<" started"<<endl;)

	pkt.prepend_sip_hdr(1); // Flag == 1 indiacates registration request
	



	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
	pkt.extract_sip_hdr();

	/*if (HMAC_ON) { // Check HMACP
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
	*/

	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(ran_ctx.xautn_num);
	pkt.extract_item(ran_ctx.rand_num); // Received Authentication information
	pkt.extract_item(ran_ctx.k_asme);
	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 1); 
	
	TRACE(cout<<"Message from PCSCF for "<<ran_ctx.imsi<<endl;)		
			
	ran_ctx.sqn = ran_ctx.rand_num + 1;
	ran_ctx.res = ran_ctx.key + ran_ctx.sqn + ran_ctx.rand_num;
	ran_ctx.autn_num = ran_ctx.res + 1;	

	if (ran_ctx.autn_num != ran_ctx.xautn_num) {
		cout << "register1:" << " authentication of SCSCF failure: " << ran_ctx.imsi << " "<<ran_ctx.autn_num<<" "<<ran_ctx.xautn_num<<" "<<ran_ctx.res<<" "<<ran_ctx.key<<" "<<ran_ctx.rand_num<<endl;
		exit(1);
	}
}
bool Ran::authenticate()
{

	uint64_t imsi;
	bool res;
	string status;

	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	pkt.append_item(ran_ctx.expiration_value);	
	pkt.append_item(ran_ctx.res);	
	imsi = ran_ctx.imsi;

	if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	} 	
	TRACE(cout<<"authenticate process for "<<ran_ctx.imsi <<" started"<<endl;)
	TRACE(cout<<imsi<<" sent Res "<<ran_ctx.res<<"\n";)

	pkt.prepend_sip_hdr(2); // Flag == 2 indiacates authenticate request
	



	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
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


	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(status);// Status of Authentication received

	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 2); 
	
	TRACE(cout<<"Message from PCSCF for "<<imsi<<" "<<status<<endl;)				
	/*
	int privateidentity;
	string status;
	bool res;
	TRACE(cout<<"Registration process for "<<ran_ctx.imsi <<" started"<<endl;)


	pkt.clear_pkt();
	pkt.append_item(ran_ctx.privateidentity);
	//pkt.append_item(ran_ctx.imsi);
	pkt.append_item(ran_ctx.instanceid);
	pkt.append_item(ran_ctx.expiration_value);	
	pkt.append_item(ran_ctx.res);
	pkt.append_item(ran_ctx.gruu);

	if (ENC_ON) {
				g_crypt.enc(pkt,ran_ctx.ik);
			}
	if (HMAC_ON) {
				g_integrity.add_hmac(pkt, ran_ctx.ck);
			}	
	pkt.prepend_sip_hdr((int)ran_ctx.imsi);					
	pkt.prepend_sip_hdr(2);
	pcscf_client.snd(pkt);
	pkt.clear_pkt();
	pcscf_client.rcv(pkt);
	pkt.extract_sip_hdr();

	if (HMAC_ON) {
	res = g_integrity.hmac_check(pkt, ran_ctx.ik);
		if (res == false) {
		TRACE(cout << " deregistration:" << " hmac failure: " << endl;)
		g_utils.handle_type1_error(-1, "hmac failure: ");
		}		
	}
	if (ENC_ON) {
		g_crypt.dec(pkt, ran_ctx.ck);
	}	
	pkt.extract_item(privateidentity);	
	pkt.extract_item(status);

	TRACE(cout<<"Message from PCSCF for Authentication "<<ran_ctx.imsi<<" is "<<status<<endl;)				

	//TRACE(cout<<"Incoming private identity authenticate "<<privateidentity<<" "<<pkt.sip_hdr.msg_type<<" "<<ran_ctx.res<<endl;)	
	return true;
	*/
}


bool Ran::deregsiter()
{
	uint64_t imsi;
	bool res;
	uint64_t registered;
	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	ran_ctx.expiration_value = 0; // Deregistration process is identified by 0 expiration value
	pkt.append_item(ran_ctx.expiration_value);	

	imsi = ran_ctx.imsi;

	if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	} 	
	TRACE(cout<<"deregsiter process for "<<ran_ctx.imsi <<" started"<<endl;)

	pkt.prepend_sip_hdr(3); // Flag == 2 indiacates authenticate request
	



	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
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


	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(registered);// 

	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 3); 
	if(registered == 0)
	{
		TRACE(cout<<imsi<<" has been deregistered\n";)
	}
	else
	{
		cout<<imsi<<" There is issue in deregistration\n";
	}
	
	/*
	int privateidentity;
	uint64_t registered;
	string status;
	TRACE(cout<<"Deregistration process for "<<ran_ctx.imsi<<" started"<<endl;)

	pkt.clear_pkt();
	bool res;
	pkt.append_item(ran_ctx.privateidentity);
	//pkt.append_item(ran_ctx.imsi);
	pkt.append_item(ran_ctx.instanceid);
	ran_ctx.expiration_value = 0;
	pkt.append_item(ran_ctx.expiration_value);
	pkt.append_item(ran_ctx.gruu);
	
	if (ENC_ON) {
				g_crypt.enc(pkt,ran_ctx.ik);
			}
	if (HMAC_ON) {
				g_integrity.add_hmac(pkt, ran_ctx.ck);
			}	
	pkt.prepend_sip_hdr((int)ran_ctx.imsi);					
	pkt.prepend_sip_hdr(3);
	pcscf_client.snd(pkt);
	pkt.clear_pkt();
	pcscf_client.rcv(pkt);
	pkt.extract_sip_hdr();
	
	if (HMAC_ON) {
	res = g_integrity.hmac_check(pkt, ran_ctx.ik);
		if (res == false) {
		TRACE(cout << " deregistration:" << " hmac failure: " << endl;)
		g_utils.handle_type1_error(-1, "hmac failure: ");
		}		
	}
	if (ENC_ON) {
		g_crypt.dec(pkt, ran_ctx.ck);
	}

	pkt.extract_item(privateidentity);
	pkt.extract_item(registered);
	pkt.extract_item(status);
	if(registered == 0)
	{
		TRACE(cout<<ran_ctx.imsi<<" Has been deregistered, Status is "<<status<<endl;)
	}		
	return true; */
}	
