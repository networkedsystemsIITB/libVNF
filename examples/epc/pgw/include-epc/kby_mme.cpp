#include "defport.h"
#include "common.h"





void run()
{
	//MTCP Setup
		char* conf_file = "server.conf";
	    	/* initialize mtcp */
		int core = 0;
		if (conf_file == NULL) {
			TRACE("You forgot to pass the mTCP startup config file!\n";)
			exit(EXIT_FAILURE);
		}

		//step 1. mtcp_init, mtcp_register_signal(optional)
		retval = mtcp_init(conf_file);
		if (retval) {
			TRACE("Failed to initialize mtcp\n";)
			exit(EXIT_FAILURE);
		}
		
		TRACE("Application initialization finished.\n";)
		
		//step 2. mtcp_core_affinitize
		mtcp_core_affinitize(core);
		
		//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
		// mtcp_epoll_create
		mctx = mtcp_create_context(core);
		if (!mctx) {
			TRACE("Failed to create mtcp context!\n";)
			return NULL;
		}
		/* register signal handler to mtcp */
		mtcp_register_signal(SIGINT, SignalHandler);
	//MTCP Setup done


	//common data
	int i,retval,returnval,cur_fd, act_type;
	struct mdata fddata;
	Packet pkt;
	int pkt_len;

	//mme data
	unordered_map<uint32_t, uint64_t> s1mme_id; /* S1_MME UE identification table: mme_s1ap_ue_id -> guti */
	unordered_map<uint64_t, UeContext> ue_ctx; /* UE context table: guti -> UeContext */
	s1mme_id.clear();
	ue_ctx.clear();


	//ran listen setup
	int ran_listen_fd;
	struct sockaddr_in mme_server_addr;

	//sgw fd
	int sgw_fd;


	ran_listen_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if(ran_listen_fd < 0)
	{
		TRACE(cout<<"Error: RAN socket call"<<endl;)
		exit(-1);
	}
	
	retval = mtcp_setsock_nonblock(mctx, ran_listen_fd);
	{
		TRACE(cout<<"Error: mtcp make nonblock"<<endl);
		exit(-1);
	}

	bzero((char *) &mme_server_addr, sizeof(mme_server_addr));
	mme_server_addr.sin_family = AF_INET;
	mme_server_addr.sin_addr.s_addr = inet_addr(mme_ip);
	mme_server_addr.sin_port = htons(mme_my_port);


	//	if(bind(ran_listen_fd, (struct sockaddr *) &mme_server_addr, sizeof(mme_server_addr)) < 0)
	retval = mtcp_bind(mctx, ran_listen_fd, (struct sockaddr *) &mme_server_addr, sizeof(mme_server_addr));
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp RAN bind call"<<endl;)
		exit(-1);
	}

	retval = mtcp_listen(mctx, ran_listen_fd, MAXCONN);
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp listen"<<endl);
		exit(-1);
	}
	//mme listen setup done

	//mtcp_epoll setup
	int numevents;
	struct mtcp_epoll_event revent;
	struct mtcp_epoll_event *return_events;
	return_events = (struct mtcp_epoll_event *) malloc (sizeof (struct mtcp_epoll_event) * MAXEVENTS);
	if (!return_events) 
	{
		TRACE(cout<<"Error: malloc failed for revents"<<endl;)
		exit(-1);
	}

	epollfd = mtcp_epoll_create(mctx, MAXEVENTS);
	if(epollfd == -1)
	{
		TRACE(cout<<"Error: mtcp mme epoll_create"<<endl;)
		exit(-1);
	}

	epevent.data.fd = ran_listen_fd;
	epevent.events = MTCP_EPOLLIN;
	retval = mtcp_epoll_ctl(mctx, epollfd, EPOLL_CTL_ADD, ran_listen_fd, &epevent);
	if(retval == -1)
	{
		TRACE(cout<<"Error: mtcp epoll_ctl_add ran"<<endl;)
		exit(-1);
	}

	while(1)
	{

		numevents = mtcp_epoll_wait(mctx, epollfd, return_events, MAXEVENTS, 1000);
		
		if(numevents < 0)
		{
			cout<<"Error: mtcp wait :"<<errno<<endl;
			if(errno != EINTR)
					cout<<"Damn error"<<endl;
			//cout<<errno<<endl;
			exit(-1);
		}

		if(numevents == 0)
		{
			TRACER(cout<<"Info: Tick Epoll Wait"<<endl;)
		}

		for(int i = 0; i < numevents; ++i)
		{
			//check for errors
			if( (return_events[i].events & EPOLLERR) ||
				(return_events[i].events & EPOLLHUP)	)
			{

				TRACE(cout<<"\n\nError: epoll event returned : "<<return_events[i].data.fd<<" errno :"<<errno<<endl;)
				if(return_events[i].data.sockid == ran_listen_fd)
				{
					TRACE(cout<<"Error: Its Ran Listen fd"<<endl;)
					cout<<"Error if in while"<<endl;
				}
				close(return_events[i].data.fd);
				continue;
			}

			revent = return_events[i];
			//Ran attach request
			if(revent.data.sockid == ran_listen_fd) 
			{
				handle_ran_accept(ran_listen_fd);
			}//
			else
			{
				cur_fd = revent.data.sockid;
				fddata = fdmap[cur_fd];
				act_type = fddata.act;

				switch(act_type)
				{
					
					
					case 1:
						//data from ran
						retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
						if(retval < 0)
						{
							cout<<"Error ran epoll read delete from epoll"<<endl;
							exit(-1);
						}

						pkt.clear_pkt();
						retval = mtcp_read(mctx, cur_fd, data, BUF_SIZE);
						if(retval < 0)
						{
							TRACE(cout<<"ERROR: read packet from ran"<<endl;)
							exit(-1);
						}
						
						memcpy(&pkt_len, data, sizeof(int));
						dataptr = data+sizeof(int);
						memcpy(pkt.data, (dataptr), pkt_len);
						pkt.data_ptr = 0;
						pkt.len = pkt_len;
						
						//Packet processing begins
						pkt.extract_s1ap_hdr();
						cout<<"HDR ID :"<<pkt.s1ap_hdr.mme_s1ap_ue_id<<endl;
						cout<<"header Id"<<pkt.s1ap_hdr.msg_type<<endl;
					
						if (pkt.s1ap_hdr.mme_s1ap_ue_id == 0) {
							//1st attach from ran
							num_autn_vectors = 1;
							pkt.extract_item(imsi);
							pkt.extract_item(tai);
							pkt.extract_item(ksi_asme); /* No use in this case */
							pkt.extract_item(nw_capability); /* No use in this case */
							cout<<"IMSI from RAN :"<<imsi<<endl;
							enodeb_s1ap_ue_id = pkt.s1ap_hdr.enodeb_s1ap_ue_id;
							guti = g_telecom.get_guti(mme_ids.gummei, imsi);
							TRACE(cout << "Info: " << " initial attach req: " << guti << endl;)
							//Locks here

							mlock(s1mmeid_mux);
							ue_count++;
							mme_s1ap_ue_id = ue_count;
							cout<<"assigned:"<<mme_s1ap_ue_id<<":"<<ue_count<<endl;
							s1mme_id[mme_s1ap_ue_id] = guti;
							munlock(s1mmeid_mux);
							
							//Locks here
							//mlock(uectx_mux);
							ue_ctx[guti].init(imsi, enodeb_s1ap_ue_id, mme_s1ap_ue_id, tai, nw_capability);
							nw_type = ue_ctx[guti].nw_type;

							//send to hss
							pkt.clear_pkt();
							pkt.append_item(imsi);
							pkt.append_item(mme_ids.plmn_id);
							pkt.append_item(num_autn_vectors);
							pkt.append_item(nw_type);
							pkt.prepend_diameter_hdr(1, pkt.len);
							pkt.prepend_len();
							
							handle_hss_connect(cur_fd, pkt);
						}//done pkt-id 0
						else
						if(pkt.s1ap_hdr.msg_type == 2)
						{
							//attach 2 from ran
							guti = 0;
							mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
							//Locks here
							if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
								guti = s1mme_id[mme_s1ap_ue_id];
							}
							
							if (guti == 0) {
								cout<<"Error: guit 0 ran_accept_fd case 2"<<endl;
								exit(-1);
							}
							pkt.extract_item(res);
								
							//Locks here
							xres = ue_ctx[guti].xres;
								
							if (res == xres)
								TRACE(cout << "mme_handleautn:" << " Authentication successful: " << guti << endl;)
							//set_crypt_context(guti);
							//Locks here
							ue_ctx[guti].nas_enc_algo = 1;
							ue_ctx[guti].k_nas_enc = ue_ctx[guti].k_asme + ue_ctx[guti].nas_enc_algo + ue_ctx[guti].count + ue_ctx[guti].bearer + ue_ctx[guti].dir;
							
							//set_integrity_context(guti);
							//Locks here
							ue_ctx[guti].nas_int_algo = 1;
							ue_ctx[guti].k_nas_int = ue_ctx[guti].k_asme + ue_ctx[guti].nas_int_algo + ue_ctx[guti].count + ue_ctx[guti].bearer + ue_ctx[guti].dir;
							
							//Locks here
							ksi_asme = ue_ctx[guti].ksi_asme;
							nw_capability = ue_ctx[guti].nw_capability;
							nas_enc_algo = ue_ctx[guti].nas_enc_algo;
							nas_int_algo = ue_ctx[guti].nas_int_algo;
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
						
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

							send_ran_attach_two(pkt)

						}
						else
						if(pkt.s1ap_hdr.msg_type == 3)
						{//Third attach request
							guti = 0;
							mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
							//Locks Deep
							if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
								guti = s1mme_id[mme_s1ap_ue_id];
							}
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
							//	g_sync.munlock(uectx_mux);

							if (HMAC_ON) {
								res = g_integrity.hmac_check(pkt, k_nas_int);
								if (res == false) {
									cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << guti << endl;
									//cout<<"Error: Hmac failed 3rd attach "<<endl;
									exit(-1);
								}		
							}
							if (ENC_ON) {
								g_crypt.dec(pkt, k_nas_enc);
							}
							pkt.extract_item(res);
							if (res == false) {
								cout << "mme_handlesecuritymodecomplete:" << " security mode complete failure: " << guti << endl;
								//cout<<"Error: res failed at 3rd attach"<<endl;
								exit(-1);
							}
							else {
								TRACE(cout << "mme_handlesecuritymodecomplete:" << " security mode complete success: " << guti << endl;)
								//Success, proceed to UDP
							}
							eps_bearer_id = 5;	//mme.cpp	l:353
							//Locks Here
							//set_pgw_info(guti);
							ue_ctx[guti].pgw_s5_port = g_pgw_s5_port;
							ue_ctx[guti].pgw_s5_ip_addr = g_pgw_s5_ip_addr;
							//g_sync.mlock(uectx_mux);
							//ue_ctx[guti].s11_cteid_mme = get_s11cteidmme(guti);
							tem = to_string(guti);
							tem = tem.substr(7, -1); /* Extracting only the last 9 digits of UE MSISDN */
							s11_cteid_mme = stoull(tem);
							ue_ctx[guti].s11_cteid_mme = s11_cteid_mme;

							ue_ctx[guti].eps_bearer_id = eps_bearer_id;
							//s11_cteid_mme = ue_ctx[guti].s11_cteid_mme;
							imsi = ue_ctx[guti].imsi;
							eps_bearer_id = ue_ctx[guti].eps_bearer_id;
							pgw_s5_ip_addr = ue_ctx[guti].pgw_s5_ip_addr;
							pgw_s5_port = ue_ctx[guti].pgw_s5_port;
							ue_ctx[guti].apn_in_use = 0;	//Added by trishal
							apn_in_use = ue_ctx[guti].apn_in_use;
							tai = ue_ctx[guti].tai;	

							pkt.clear_pkt();
							pkt.append_item(s11_cteid_mme);
							pkt.append_item(imsi);
							pkt.append_item(eps_bearer_id);
							pkt.append_item(pgw_s5_ip_addr);
							pkt.append_item(pgw_s5_port);
							pkt.append_item(apn_in_use);
							pkt.append_item(tai);
							pkt.prepend_gtp_hdr(2, 1, pkt.len, 0);

							handle_sgw_connect(cur_fd, pkt, mme_s1ap_ue_id );
						}
						else
						if(pkt.s1ap_hdr.msg_type == 4)
						{
							//4th attach
							guti = 0;		//mme.cpp	l:438
							mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
								
							//Locks Deep
							//g_sync.mlock(s1mmeid_mux);
							if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
								guti = s1mme_id[mme_s1ap_ue_id];
							}
							//g_sync.munlock(s1mmeid_mux);
							//	g_sync.mlock(uectx_mux);
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
							//	g_sync.munlock(uectx_mux);

							if (HMAC_ON) {
								res = g_integrity.hmac_check(pkt, k_nas_int);
								if (res == false) {
									TRACE(cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << guti << endl;)
									//cout<<"Error: Hmac failed 3rd attach "<<endl;
									exit(-1);
								}		
							}
							if (ENC_ON) {
								g_crypt.dec(pkt, k_nas_enc);
							}

							pkt.extract_item(eps_bearer_id);
							pkt.extract_item(s1_uteid_dl);
							//g_sync.mlock(uectx_mux);
							ue_ctx[guti].s1_uteid_dl = s1_uteid_dl;
							ue_ctx[guti].emm_state = 1;
							//g_sync.munlock(uectx_mux);
							TRACE(cout << "mme_handleattachcomplete:" << " attach completed: " << guti << endl;)

							//Locks here
							//g_sync.mlock(uectx_mux);
							eps_bearer_id = ue_ctx[guti].eps_bearer_id;
							s1_uteid_dl = ue_ctx[guti].s1_uteid_dl;
							s11_cteid_sgw = ue_ctx[guti].s11_cteid_sgw;

							pkt.clear_pkt();
							pkt.append_item(eps_bearer_id);
							pkt.append_item(s1_uteid_dl);
							pkt.append_item(g_trafmon_ip_addr);
							pkt.append_item(g_trafmon_port);
							pkt.prepend_gtp_hdr(2, 2, pkt.len, s11_cteid_sgw);

							fddata.msui = mme_s1ap_ue_id;
							send_sgw_afour(cur_fd, fddata, pkt);

						}
						else
						if(pkt.s1ap_hdr.msg_type == 5)
						{
							//detach request
							//Detach request
							guti = 0;		//mme.cpp	l:438
							mme_s1ap_ue_id = pkt.s1ap_hdr.mme_s1ap_ue_id;
								
							//Locks Deep
							//g_sync.mlock(s1mmeid_mux);
							if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
								guti = s1mme_id[mme_s1ap_ue_id];
							}
							//g_sync.munlock(s1mmeid_mux);
							//	g_sync.mlock(uectx_mux);
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
							eps_bearer_id = ue_ctx[guti].eps_bearer_id;
							tai = ue_ctx[guti].tai;
							s11_cteid_sgw = ue_ctx[guti].s11_cteid_sgw;
							//	g_sync.munlock(uectx_mux);
							if (HMAC_ON) {
								res = g_integrity.hmac_check(pkt, k_nas_int);
								if (res == false) {
									cout << "mme_handlesecuritymodecomplete:" << " hmac failure: " << guti << endl;
									//cout<<"Error: Hmac failed 3rd attach "<<endl;
									exit(-1);
								}		
							}
							if (ENC_ON) {
								g_crypt.dec(pkt, k_nas_enc);
							}

							pkt.extract_item(guti); //Check Same???	mme.cpp-l558
							pkt.extract_item(ksi_asme);
							pkt.extract_item(detach_type);	
								
							//MME-SGW
							pkt.clear_pkt();
							pkt.append_item(eps_bearer_id);
							pkt.append_item(tai);
							pkt.prepend_gtp_hdr(2, 3, pkt.len, s11_cteid_sgw);
							
							send_sgw_detach(cur_fd, pkt);
						}
						else
						{
							cout<<"Wrong packet header \n"<<endl;
							exit(-1);
						}
						break;	// case 1

					case 2:
						//Connect to hss done
						if(return_events[i].events & MTCP_EPOLLOUT)
						{
							send_request_hss(cur_fd, fddata);
						}
						else
						{
							cout<<"Error: Case 2 hss connect Wrong Event";
							exit(-1);
						}
					break; // case 2

					case 3:
						//Data from hss
						retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
						if(retval < 0)
						{
							cout<<"Error ran epoll read delete from epoll"<<endl;
							exit(-1);
						}

						pkt.clear_pkt();
						retval = mtcp_read(mctx, cur_fd, data,BUF_SIZE);
						if(retval <= 0)
						{
							cout<<"Error: hsss read packet"<<errno<<endl;
							exit(-1);
						}
						memcpy(&pkt_len, data, sizeof(int));
						dataptr = data+sizeof(int);
						memcpy(pkt.data, (dataptr), pkt_len);
						pkt.data_ptr = 0;
						pkt.len = pkt_len;
						mtcp_close(mctx, cur_fd);

						pkt.extract_diameter_hdr();
						pkt.extract_item(autn_num);
						pkt.extract_item(rand_num);
						pkt.extract_item(xres);
						pkt.extract_item(k_asme);

						mme_s1ap_ue_id = fddata.msui;
						//cout<<"Stored msui"<<fddata.msui<<" hss "<<cur_fd<<" xres "<<xres<<endl;
						
						//mlock(s1mmeid_mux);
							if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
								guti = s1mme_id[mme_s1ap_ue_id];
							}
						//munlock(s1mmeid_mux);
						
						//Locks here
						//mlock(uectx_mux);
						ue_ctx[guti].xres = xres;
						ue_ctx[guti].k_asme = k_asme;
						ue_ctx[guti].ksi_asme = 1;
						ksi_asme = ue_ctx[guti].ksi_asme;
						enodeb_s1ap_ue_id = ue_ctx[guti].enodeb_s1ap_ue_id;
						//munlock(uectx_mux);
						cout<<"HSS Sent :"<<guti<<endl;
						//TRACE(cout << "Info:mme_handleinitialattach:" << " autn:" << autn_num <<" rand:" << rand_num << " xres:" << xres << " k_asme:" << k_asme << " " << guti << endl;)

						pkt.clear_pkt();
						pkt.append_item(autn_num);
						pkt.append_item(rand_num);
						pkt.append_item(ksi_asme);
						
						pkt.prepend_s1ap_hdr(1, pkt.len, enodeb_s1ap_ue_id, mme_s1ap_ue_id);
						pkt.prepend_len();
						ran_accept_fd = fddata.initial_fd;
						fdmap.erase(cur_fd);
						send_ran_attach_one(cur_fd, ran_accept_fd, pkt)
						

					break; //case 3

					case 4:
						//Connect to sgw done
						if(return_events[i].events & MTCP_EPOLLOUT)
						{
							send_request_sgw_athree(cur_fd, fddata);
						}
						else
						{
							cout<<"Error: Case 4 sgw connect Wrong Event";
							exit(-1);
						}
					break; //case 4

					case 5:
						//a3 response from sgw
						retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
						if(retval < 0)
						{
							cout<<"Error ran epoll read delete from epoll"<<endl;
							exit(-1);
						}

						pkt.clear_pkt();
						retval = mtcp_read(mctx, cur_fd, data,BUF_SIZE);
						if(retval <= 0)
						{
							cout<<"Error: hsss read packet"<<errno<<endl;
							exit(-1);
						}
						memcpy(&pkt_len, data, sizeof(int));
						dataptr = data+sizeof(int);
						memcpy(pkt.data, (dataptr), pkt_len);
						pkt.data_ptr = 0;
						pkt.len = pkt_len;
						
						ran_accept_fd = fddata.initial_fd;
						mme_s1ap_ue_id = fddata.msui;
						if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
							guti = s1mme_id[mme_s1ap_ue_id];
						}

						pkt.extract_gtp_hdr();
						pkt.extract_item(s11_cteid_sgw);
						pkt.extract_item(ue_ip_addr);
						pkt.extract_item(s1_uteid_ul);
						pkt.extract_item(s5_uteid_ul);
						pkt.extract_item(s5_uteid_dl);
						//locks here
						ue_ctx[guti].ip_addr = ue_ip_addr;
						ue_ctx[guti].s11_cteid_sgw = s11_cteid_sgw;
						ue_ctx[guti].s1_uteid_ul = s1_uteid_ul;
						ue_ctx[guti].s5_uteid_ul = s5_uteid_ul;
						ue_ctx[guti].s5_uteid_dl = s5_uteid_dl;
						ue_ctx[guti].tai_list.clear();
						ue_ctx[guti].tai_list.push_back(ue_ctx[guti].tai);
						ue_ctx[guti].tau_timer = g_timer;
						ue_ctx[guti].e_rab_id = ue_ctx[guti].eps_bearer_id;
						ue_ctx[guti].k_enodeb = ue_ctx[guti].k_asme;
						e_rab_id = ue_ctx[guti].e_rab_id;
						k_enodeb = ue_ctx[guti].k_enodeb;
						nw_capability = ue_ctx[guti].nw_capability;
						tai_list = ue_ctx[guti].tai_list;
						tau_timer = ue_ctx[guti].tau_timer;
						k_nas_enc = ue_ctx[guti].k_nas_enc;
						k_nas_int = ue_ctx[guti].k_nas_int;
						//
						epsres = true;
						tai_list_size = 1;	

						pkt.clear_pkt();							
						//pkt.data_ptr = 0;
						pkt.append_item(guti);
						pkt.append_item(eps_bearer_id);
						pkt.append_item(e_rab_id);
						pkt.append_item(s1_uteid_ul);
						pkt.append_item(k_enodeb);
						pkt.append_item(nw_capability);
						pkt.append_item(tai_list_size);
						pkt.append_item(tai_list);
						pkt.append_item(tau_timer);
						pkt.append_item(ue_ip_addr);
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
						returnval = write_stream(ran_accept_fd, pkt.data, pkt.len);
						if(returnval < 0)
						{
							cout<<"Error: Cant send to RAN"<<endl;
						
							exit(-1);
						}
						//cout<<"Sent: guti: "<<guti<<" res :"<<res<<endl;
						TRACE(cout<<"Info Attach 3: Data send to RAN:"<<guti<<endl;)
						fdmap.erase(cur_fd);
						epevent.data.sockid = ran_accept_fd;
						epevent.events = MTCP_EPOLLIN;
						returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_accept_fd, &epevent);
						if(returnval == -1)
						{
							cout<<"Error: ran after detach add mtcp error"<<endl;
							exit(-1);
						}	

						fddata.act = 1;
						fddata.initial_fd = cur_fd; 
						memset(fddata.buf,0,500);
						fddata.msui = 0;
						fddata.buflen = 0;
						fdmap.insert(make_pair(ran_accept_fd,fddata));

					break;//case 5

					case 6:
						//a4 response from sgw
						retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
						if(retval < 0)
						{
							cout<<"Error ran epoll read delete from epoll"<<endl;
							exit(-1);
						}

						pkt.clear_pkt();
						retval = mtcp_read(mctx, cur_fd, data,BUF_SIZE);
						if(retval <= 0)
						{
							cout<<"Error: hsss read packet"<<errno<<endl;
							exit(-1);
						}
						memcpy(&pkt_len, data, sizeof(int));
						dataptr = data+sizeof(int);
						memcpy(pkt.data, (dataptr), pkt_len);
						pkt.data_ptr = 0;
						pkt.len = pkt_len;
						
						ran_accept_fd = fddata.initial_fd;
						mme_s1ap_ue_id = fddata.msui;
						if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
							guti = s1mme_id[mme_s1ap_ue_id];
						}

						pkt.extract_gtp_hdr();
						pkt.extract_item(res);
						if (res == false) {
							cout << "mme_handlemodifybearer:" << " modify bearer failure: " << guti << endl;
						}
						else {
							//g_sync.mlock(uectx_mux);
							ue_ctx[guti].ecm_state = 1;
							nw_capability = ue_ctx[guti].nw_capability;
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
							//g_sync.munlock(uectx_mux);
							TRACE(cout << "mme_handlemodifybearer:" << " eps session setup success: " << guti << endl;)
							//cout << "mme_handlemodifybearer:" << " eps session setup success: " << guti << endl;
						}
						epsres = true;
						pkt.clear_pkt();
						//pkt.data_ptr = 0;
						pkt.append_item(epsres);
						pkt.append_item(guti);
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
						returnval = write_stream(ran_accept_fd, pkt.data, pkt.len);
						
						if(returnval < 0)
						{
							cout<<"Error: Cant send to RAN"<<endl;
							exit(-1);
						}
						
						epevent.data.sockid = ran_accept_fd;
						epevent.events = MTCP_EPOLLIN;
						returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_accept_fd, &epevent);
						if(returnval == -1)
						{
							cout<<"Error: ran after detach add mtcp error"<<endl;
							exit(-1);
						}	

						fddata.act = 1;
						fddata.initial_fd = cur_fd; 
						memset(fddata.buf,0,500);
						fddata.msui = 0;
						fddata.buflen = 0;
						fdmap.erase(cur_fd);
						fdmap.insert(make_pair(ran_accept_fd,fddata));


					break;//case 6

					case 7:
						//detach sgw->mme->ran
						retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, &epevent);
						if(retval < 0)
						{
							cout<<"Error ran epoll read delete from epoll"<<endl;
							exit(-1);
						}

						pkt.clear_pkt();
						retval = mtcp_read(mctx, cur_fd, data,BUF_SIZE);
						if(retval <= 0)
						{
							cout<<"Error: hsss read packet"<<errno<<endl;
							exit(-1);
						}
						memcpy(&pkt_len, data, sizeof(int));
						dataptr = data+sizeof(int);
						memcpy(pkt.data, (dataptr), pkt_len);
						pkt.data_ptr = 0;
						pkt.len = pkt_len;
						
						ran_accept_fd = fddata.initial_fd;
						mme_s1ap_ue_id = fddata.msui;
						if (s1mme_id.find(mme_s1ap_ue_id) != s1mme_id.end()) {
							guti = s1mme_id[mme_s1ap_ue_id];
						}

						pkt.extract_gtp_hdr();
						pkt.extract_item(res);
						if (res == false) {
							cout << "mme_handlemodifybearer:" << " modify bearer failure: " << guti << endl;
						}
						else {
							//g_sync.mlock(uectx_mux);
							//ue_ctx[guti].ecm_state = 1;
							//nw_capability = ue_ctx[guti].nw_capability;
							k_nas_enc = ue_ctx[guti].k_nas_enc;
							k_nas_int = ue_ctx[guti].k_nas_int;
							//g_sync.munlock(uectx_mux);
							//TRACE(cout << "mme_handlemodifybearer:" << " eps session setup success: " << guti << endl;		)
							//cout << "mme_handlemodifybearer:" << " eps session setup success: " << guti << endl;
						}

						epsres = true;
						//cout<<"sending "<<guti<<" port "<<udp_detach_port<<endl;
						pkt.clear_pkt();
						//pkt.data_ptr = 0;
						pkt.append_item(epsres);
						//pkt.append_item(guti);
						//pkt.append_item(nw_capability);
						if (ENC_ON) {
							g_crypt.enc(pkt, k_nas_enc);
						}
						if (HMAC_ON) {
							g_integrity.add_hmac(pkt, k_nas_int);
						}
						pkt.prepend_s1ap_hdr(5, pkt.len, pkt.s1ap_hdr.enodeb_s1ap_ue_id, pkt.s1ap_hdr.mme_s1ap_ue_id);
						//headers not verified at client side...
						pkt.prepend_len();
						returnval = write_stream(ran_accept_fd, pkt.data, pkt.len);
						if(returnval < 0)
						{
							cout<<"Error: Cant send to RAN"<<endl;
							exit(-1);
						}
						TRACE(cout<<"Info:Done detach to RAN"<<endl;)
						//cout<<" 	sent"<<endl;
						mtcp_close(mctx, cur_fd);
						//mme.cpp l:591, mme.cpp l:618-624
						//g_sync.mlock(s1mmeid_mux);
						s1mme_id.erase(mme_s1ap_ue_id);
						//g_sync.mlock(uectx_mux);
						ue_ctx.erase(guti);
						//g_sync.munlock(uectx_mux);
								
						fdmap.erase(cur_fd);
						//close(ran_accept_fd);
								
						fdmap.erase(ran_accept_fd);
						
						epevent.data.sockid = ran_accept_fd;
						epevent.events = MTCP_EPOLLIN;
						returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_accept_fd, &epevent);
						if(returnval == -1)
						{
							cout<<"Error: ran after detach add mtcp error"<<endl;
							exit(-1);
						}		
								
						fddata.act = 1;
						fddata.initial_fd = 0; 
						memset(fddata.buf,0,500);
						fddata.msui = 0;
						fddata.buflen = 0;
						fdmap.insert(make_pair(ran_accept_fd,fddata));

					break;//case 6

					default:
						cout<<"Error unknown switch case"<<endl;

					break;//default
				}//switch close;
			}//close for action events
		}//for i-numevents loop ends
	}//end while(1);

}//end run()


void handle_ran_accept(int ran_listen_fd)
{
	int ran_accept_fd, retval;
	struct mdata fddata;

	while(1)
	{

		ran_accept_fd = mtcp_accept(mctx, ran_listen_fd, NULL, NULL);
		if(ran_accept_fd < 0)
			{//
			if((errno == EAGAIN) ||	(errno == EWOULDBLOCK))
			{
				break;
			}
			else
			{
				perror("mtcp error : error on accetpt ");
				cout<<"Error on accept"<<endl;
				exit(-1);
				//break;
			}
		}
		//perror("mtcp error 11");
		epevent.events = MTCP_EPOLLIN;
		epevent.data.sockid = ran_accept_fd;
		mtcp_setsock_nonblock(mctx, ran_accept_fd);
		retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_accept_fd, &epevent);
		if(retval < 0)
		{
			cout<<"Error adding ran accept to epoll"<<endl;
			exit(-1);
		}			
		fddata.act = 1;
		fddata.initial_fd = 0;
		fddata.msui = 0;
		memset(fddata.buf,'\0',500);
		fddata.buflen = 0;
		fdmap.insert(make_pair(ran_accept_fd, fddata));
		//cout<<" Accepted Done"<<endl;
	}
}

void handle_hss_connect(int cur_fd, Packet pkt)
{

	int hss_fd,retval;
	struct mdata fddata;
	struct sockaddr_in hss_server_addr;

	bzero((char *) &hss_server_addr, sizeof(hss_server_addr));
	hss_server_addr.sin_family = AF_INET;
	hss_server_addr.sin_addr.s_addr = inet_addr(hss_ip);
	hss_server_addr.sin_port = htons(hss_my_port);

	hss_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if(hss_fd < 0)
	{
		cout<<"Error: hss new socket fd error"<<endl;
		exit(-1);
	}
	retval = mtcp_setsock_nonblock(mctx, hss_fd);
	if(retval < 0)
	{
		cout<<"Error: create hss nonblock"<<endl;
		exit(-1);
	}
	
	retval = mtcp_connect(mctx, hss_fd, (struct sockaddr *)&hss_server_addr, sizeof(struct sockaddr_in));
	
	if((retval < 0) && (errno == EINPROGRESS))
	{
		//Connect in end;
		epevent.events =  MTCP_EPOLLOUT;
		epevent.data.sockid = hss_fd;
		returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, hss_fd, &epevent);
		if(returnval == -1)
		{
			cout<<"Error: epoll hss add"<<endl;
			exit(-1);
		}
		//cout<<"pkt.len"<<pkt.len<<endl;
		fdmap.erase(cur_fd);
		fddata.act = 2;
		fddata.initial_fd = cur_fd;
		fddata.msui = mme_s1ap_ue_id;
		memcpy(fddata.buf, pkt.data, pkt.len);
		fddata.buflen = pkt.len;
		cout<<"pkt.len"<<fddata.buflen<<" Buffer "<<fddata.buf<<endl;
		fdmap.insert(make_pair(hss_fd, fddata));
	}
	else
	if(retval < 0)
	{
		cout<<"Error: mtcp hss connect error"<<endl;
		exit(-1);
	}
	else
	{
		cout<<"Unexpected happened: Hss connect immedietly, handle this now\n";
		exit(-1);
	}
}

void send_request_hss(int cur_fd, struct mdata fddata)
{
	cout<<"MTCP Connect in PROGRESS connected"<<endl;
	returnval = mtcp_write(mctx, cur_fd, fddata.buf, fddata.buflen);
	cout<<"Written:"<<returnval<<endl;
	if(returnval < 0)
	{
		cout<<"Error: hss write after connect"<<errno<<endl;
		exit(-1);
	}
	epevent.data.sockid = cur_fd;
	epevent.events = MTCP_EPOLLIN;
	returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_MOD, cur_fd, &epevent);
	if(returnval == -1)
	{
		cout<<"Error: Hss listen add mtcp error"<<endl;
		exit(-1);
	}
	fdmap.erase(cur_fd);
	cout<<fddata.msui<<" check these "<<fddata.initial_fd<<endl;
	fddata.act = 3;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fdmap.insert(make_pair(cur_fd, fddata));
}

void send_ran_attach_one(int cur_fd, Packet pkt)
{	
	int retval;
	retval = mtcp_write(mctx, cur_fd,  pkt.data, pkt.len);
	if(retval < 0)
	{
		cout<<"Error MME write back to RAN"<<endl;
		exit(-1);
	}

	//fdmap.erase(ran_accept_fd);
	fdmap.erase(cur_fd);
	epevent.events = MTCP_EPOLLIN;
	epevent.data.sockid = cur_fd;
	
	retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, cur_fd, &epevent);
	if(retval < 0)
	{
		TRACE(cout<<"Error adding ran for attach 2 to epoll"<<endl;)
		exit(-1);
	}
	fddata.act = 1;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fdmap.insert(make_pair(cur_fd, fddata));
}

void send_ran_attach_two(int cur_fd, Packet pkt)
{
	int retval;
	retval = mtcp_write(mctx, cur_fd,  pkt.data, pkt.len);
	if(retval < 0)
	{
		cout<<"Error MME write back to RAN"<<endl;
		exit(-1);
	}

	//fdmap.erase(ran_accept_fd);
	fdmap.erase(cur_fd);
	epevent.events = MTCP_EPOLLIN;
	epevent.data.sockid = cur_fd;
	
	retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, cur_fd, &epevent);
	if(retval < 0)
	{
		TRACE(cout<<"Error adding ran for attach 2 to epoll"<<endl;)
		exit(-1);
	}
	fddata.act = 1;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fdmap.insert(make_pair(cur_fd, fddata));
}

void handle_sgw_connect(int cur_fd, Packet pkt, int msui)
{

	int sgw_fd,retval;
	struct mdata fddata;
	struct sockaddr_in sgw_server_addr;

	bzero((char *) &sgw_server_addr, sizeof(sgw_server_addr));
	sgw_server_addr.sin_family = AF_INET;
	sgw_server_addr.sin_addr.s_addr = inet_addr(sgw_ip);
	sgw_server_addr.sin_port = htons(sgw_my_port);

	sgw_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if(sgw_fd < 0)
	{
		cout<<"Error: hss new socket fd error"<<endl;
		exit(-1);
	}
	retval = mtcp_setsock_nonblock(mctx, sgw_fd);
	if(retval < 0)
	{
		cout<<"Error: create hss nonblock"<<endl;
		exit(-1);
	}
	
	retval = mtcp_connect(mctx, sgw_fd, (struct sockaddr *)&sgw_server_addr, sizeof(struct sockaddr_in));
	
	if((retval < 0) && (errno == EINPROGRESS))
	{
		//Connect in end;
		epevent.events =  MTCP_EPOLLOUT;
		epevent.data.sockid = sgw_fd;
		returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, sgw_fd, &epevent);
		if(returnval == -1)
		{
			cout<<"Error: epoll sgw add"<<endl;
			exit(-1);
		}
		//cout<<"pkt.len"<<pkt.len<<endl;
		fdmap.erase(cur_fd);
		fddata.act = 4;
		fddata.initial_fd = cur_fd;
		fddata.msui = msui;
		memcpy(fddata.buf, pkt.data, pkt.len);
		fddata.buflen = pkt.len;
		//cout<<"pkt.len"<<fddata.buflen<<" Buffer "<<fddata.buf<<endl;
		fdmap.insert(make_pair(sgw_fd, fddata));
	}
	else
	if(retval < 0)
	{
		cout<<"Error: mtcp sgw connect error"<<endl;
		exit(-1);
	}
	else
	{
		cout<<"Unexpected happened: sgw connect immedietly, handle this now\n";
		exit(-1);
	}
}

void send_request_sgw_athree(int cur_fd, struct mdata fddata)
{
	cout<<"MTCP SGW Connect in PROGRESS connected"<<endl;
	returnval = mtcp_write(mctx, cur_fd, fddata.buf, fddata.buflen);
	//cout<<"Written:"<<returnval<<endl;
	if(returnval < 0)
	{
		cout<<"Error: sgw write after connect"<<errno<<endl;
		exit(-1);
	}
	epevent.data.sockid = cur_fd;
	epevent.events = MTCP_EPOLLIN;
	returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_MOD, cur_fd, &epevent);
	if(returnval == -1)
	{
		cout<<"Error: sgw receive athree add mtcp error"<<endl;
		exit(-1);
	}
	fdmap.erase(cur_fd);
	cout<<fddata.msui<<" check these "<<fddata.initial_fd<<endl;
	fddata.act = 5;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fdmap.insert(make_pair(cur_fd, fddata));
}

void send_sgw_afour(int cur_fd, struct mdata fddata, Packet pkt)
{
	int sgw_fd = fddata.initial_fd;
	
	returnval = mtcp_write(mctx, sgw_fd, pkt.data, pkt.len);
	//cout<<"Written:"<<returnval<<endl;
	if(returnval < 0)
	{
		cout<<"Error: sgw write after connect"<<errno<<endl;
		exit(-1);
	}
	
	epevent.data.sockid = sgw_fd;
	epevent.events = MTCP_EPOLLIN;
	returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, sgw_fd, &epevent);
	if(returnval == -1)
	{
		cout<<"Error: sgw receive afour add mtcp error"<<endl;
		exit(-1);
	}
	fdmap.erase(cur_fd);
	//cout<<fddata.msui<<" check these "<<fddata.initial_fd<<endl;
	fddata.act = 6;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fddata.initial_fd = cur_fd;
	fdmap.insert(make_pair(sgw_fd, fddata));

}

void send_sgw_detach(int cur_fd, Packet pkt)
{
	struct mdata fddata = fdmap[cur_fd];
	int sgw_fd = fddata.initial_fd;
	
	returnval = mtcp_write(mctx, sgw_fd, pkt.data, pkt.len);
	//cout<<"Written:"<<returnval<<endl;
	if(returnval < 0)
	{
		cout<<"Error: sgw write after connect"<<errno<<endl;
		exit(-1);
	}
	
	epevent.data.sockid = sgw_fd;
	epevent.events = MTCP_EPOLLIN;
	returnval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, sgw_fd, &epevent);
	if(returnval == -1)
	{
		cout<<"Error: sgw receive detach add mtcp error"<<endl;
		exit(-1);
	}
	fdmap.erase(cur_fd);
	//cout<<fddata.msui<<" check these "<<fddata.initial_fd<<endl;
	fddata.act = 7;
	fddata.buflen = 0;
	memset(fddata.buf, '\0', 500);
	fddata.initial_fd = cur_fd;
	fdmap.insert(make_pair(sgw_fd, fddata));
}

int main()
{

	mux_init(s1mmeid_mux);
	mux_init(uectx_mux);

	run();
	return 0;
}



