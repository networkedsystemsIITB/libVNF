int get_scscf(uint64_t imsi,string &scscfaddress,uint64_t &scscfport);
void handle_autninfo_req(Packet &pkt, uint64_t imsi);
void get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num);
void handleregreq_auth(int vnfconn_id, void* request, void* packet, int packetlen, int temp);
void handleRegistrationRequest(int vnfconn_id, void *request, char *packet, int packetlen, int temp);