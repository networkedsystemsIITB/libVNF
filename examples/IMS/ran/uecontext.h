class UEcontext
{
public:
	int sipheader;
	int emm_state; /* EPS Mobililty Management state */
	/* UE id */
	uint64_t imsi; /* International Mobile Subscriber Identity.  */
	int privateidentity; 
	uint64_t instanceid;
	uint64_t gruu; /* GRUU
	/* Network Operator info */
	uint16_t mcc; /* Mobile Country Code */
	uint16_t mnc; /* Mobile Network Code */
	uint16_t plmn_id; /* Public Land Mobile Network ID */	
	std::string ip_addr; // Stores IP Address of UE
	uint64_t msisdn; /* Mobile Station International Subscriber Directory Number - Mobile number */
	uint64_t expiration_value ; // 0 in case of deregistration, otherwise non zero
	/* UE security context */
	uint64_t key; /* Primary key used in generating secondary keys */
	uint64_t k_asme; /* Key for Access Security Management Entity */
	uint64_t ksi_asme; /* Key Selection Identifier for Access Security Management Entity */
	uint64_t k_nas_enc; /* Key for NAS Encryption / Decryption */
	uint64_t k_nas_int; /* Key for NAS Integrity check */
	uint64_t nas_enc_algo; /* Idenitifier of NAS Encryption / Decryption */
	uint64_t nas_int_algo; /* Idenitifier of NAS Integrity check */
	uint64_t count;
	uint64_t integrity_protected;

	uint64_t autn_num;
	uint64_t rand_num;
	uint64_t xres;
	uint64_t res;
	uint64_t ck;
	uint64_t ik;
	uint64_t expiration_time;
	uint64_t registered;
	std::string scscf_addr; // Stores IP Address of SCSCF
	uint64_t scscf_port; // SCSCF Port
};
