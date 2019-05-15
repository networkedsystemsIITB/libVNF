#include "defport.h"
#include "kby_sgw.h"


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



	//sgw specific: 
	unordered_map<uint32_t, uint64_t> s11_id; /* S11 UE identification table: s11_cteid_sgw -> imsi */
	unordered_map<uint32_t, uint64_t> s1_id; /* S1 UE identification table: s1_uteid_ul -> imsi */
	unordered_map<uint32_t, uint64_t> s5_id; /* S5 UE identification table: s5_uteid_dl -> imsi */
	unordered_map<uint64_t, UeContext> ue_ctx; /* UE context table: imsi -> UeContext */
	s11_id.clear();
	s1_id.clear();
	s5_id.clear();
	ue_ctx.clear();

	int i,retval,returnval,cur_fd, act_type;
	struct mdata fddata;
	Packet pkt;
	int pkt_len;

	int listen_fd;
	struct sockaddr_in sgw_server_addr;

	listen_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
	if(listen_fd < 0)
	{
		TRACE(cout<<"Error: SGW listen socket call"<<endl;)
		exit(-1);
	}
	
	retval = mtcp_setsock_nonblock(mctx, listen_fd);
	{
		TRACE(cout<<"Error: mtcp make nonblock"<<endl);
		exit(-1);
	}

	bzero((char *) &sgw_server_addr, sizeof(sgw_server_addr));
	sgw_server_addr.sin_family = AF_INET;
	sgw_server_addr.sin_addr.s_addr = inet_addr(sgw_ip);
	sgw_server_addr.sin_port = htons(sgw_s11_port);


	//	if(bind(ran_listen_fd, (struct sockaddr *) &mme_server_addr, sizeof(mme_server_addr)) < 0)
	retval = mtcp_bind(mctx, listen_fd, (struct sockaddr *) &sgw_server_addr, sizeof(sgw_server_addr));
	if(retval < 0)
	{
		TRACE(cout<<"Error: mtcp listenfd  bind call"<<endl;)
		exit(-1);
	}

	retval = mtcp_listen(mctx, listen_fd, MAXCONN);
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

	epevent.data.fd = listen_fd;
	epevent.events = MTCP_EPOLLIN;
	retval = mtcp_epoll_ctl(mctx, epollfd, EPOLL_CTL_ADD, listen_fd, &epevent);
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
			//TRACE(cout<<"Info: Tick Epoll Wait"<<endl;)
		}

		for(int i = 0; i < numevents; ++i)
		{

			if( (return_events[i].events & EPOLLERR) ||
				(return_events[i].events & EPOLLHUP) )
			{

				TRACE(cout<<"\n\nError: epoll event returned : "<<return_events[i].data.fd<<" errno :"<<errno<<endl;)
				if(return_events[i].data.sockid == listen_fd)
				{
					TRACE(cout<<"Error: Its Ran Listen fd"<<endl;)
					cout<<"Error if in while"<<endl;
				}
				close(return_events[i].data.fd);
				continue;
			}

			revent = return_events[i];
			//Ran attach request
			if(revent.data.sockid == listen_fd) 
			{
				handle_sgw_accept(listen_fd);
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
							cout<<"Error mme epoll read delete from epoll"<<endl;
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

					break;
				}//close switch
			}//end other events;
		}//end for i events
	}//close while
}//end run()



int main()
{

	mux_init(s11id_mux);	
	mux_init(s1id_mux);	
	mux_init(s5id_mux);	
	mux_init(uectx_mux);	

	run();
	return 0;
}


void handle_sgw_accept(int sgw_listen_fd)
{
	int sgw_accept_fd, retval;
	struct mdata fddata;

	while(1)
	{

		sgw_accept_fd = mtcp_accept(mctx, sgw_listen_fd, NULL, NULL);
		if(sgw_accept_fd < 0)
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
		epevent.data.sockid = sgw_accept_fd;
		mtcp_setsock_nonblock(mctx, sgw_accept_fd);
		retval = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, sgw_accept_fd, &epevent);
		if(retval < 0)
		{
			cout<<"Error adding ran accept to epoll"<<endl;
			exit(-1);
		}			
		fddata.act = 1;
		fddata.initial_fd = 0;
		fddata.idfr = 0;
		memset(fddata.buf,'\0',500);
		fddata.buflen = 0;
		fdmap.insert(make_pair(sgw_accept_fd, fddata));
		//cout<<" Accepted Done"<<endl;
	}
}