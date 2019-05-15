#define ran_my_port 2000
#define mme_my_port 3000
#define hss_my_port 4000
#define sgw_s11_port 7000			//cp 
#define sgw_s1_portnum 7100			//up 
#define sgw_s5_portnum 7200			//down
#define pgw_s5_portnum  8000		//CP,up 
#define pgw_sgi_portnum  8100		//down
#define sink_portnum  8500

//	mme-sgw-attach-udp
//#define udp_mme_sgw_attach_begin	21000
//#define	udp_mme_sgw_attach_end	21999

#define udp_slot_size 999
#define udp_slot_one	21000		// used for attach 3 req in mme
#define udp_slot_two	22000		// for attach 4 request in mme
#define udp_slot_three	23000


#define hss_ip "169.254.9.3"
#define mme_ip "169.254.8.254"
#define ran_ip "169.254.9.3"
#define sgw_ip "10.129.26.93"
#define pgw_ip "10.129.28.205"
#define sink_ip "10.129.41.57"


#define DEBUGPRE 0
#define TRACEP(x) if (DEBUGPRE) { x }

#define DEBUGMAIN 1
#define TRACEM(x) if (DEBUGMAIN) { x }