#include "utils.h"

Utils g_utils;

/* Action - Exit the program */
void Utils::handle_type1_error(int arg, string msg) {
	if (arg < 0) {
		msg = to_string(errno) + ": " + msg;
		perror(msg.c_str());
		exit(EXIT_FAILURE);
	}	
}

/* Action - Check for error conditions. Do not exit. */
void Utils::handle_type2_error(int arg, string msg) {
	if (arg < 0) {
		msg = to_string(errno) + ": " + msg;
		perror(msg.c_str());
	}
}

char* Utils::allocate_str_mem(int len) {
	char *tem;

	if (len <= 0) {
		handle_type1_error(-1, "Memory length error: utils_allocatestrmem");
	}
	tem = (char*)malloc(len * sizeof (char));
	if (tem != NULL) {
		memset(tem, 0, len * sizeof (char));
		return tem;
	}
	else {
		handle_type1_error(-1, "Memory allocation error: utils_allocatestrmem");
	}
}

uint8_t* Utils::allocate_uint8_mem(int len) {
	uint8_t *tem;

	if (len <= 0) {
		handle_type1_error(-1, "Memory length error: utils_allocateuint8mem");
	}
	tem = (uint8_t*)malloc(len * sizeof (uint8_t));
	if (tem != NULL) {
		memset(tem, 0, len * sizeof (uint8_t));
		return tem;
	} 
	else {
		handle_type1_error(-1, "Memory allocation error: utils_allocateuint8mem");
	}
}

void Utils::time_check(time_t start_time, double dur_time, bool &time_exceeded) {
	double elapsed_time;

	if ((elapsed_time = difftime(time(0), start_time)) > dur_time) {
		time_exceeded = true;
	}
}

int Utils::max_ele(vector<int> inp) {
	int ans;
	int size;
	int i;
	
	ans = 0;
	size = inp.size();
	for (i = 0; i < size; i++) {
		ans = max(ans, inp[i]);
	} 
	return ans;
}

int Utils::HandleIncomingSocket( int epollfd, int ran_listen_fd, epoll_event &epevent, map<int, mdata> &fdmap, mdata &fddata)
{
	int ran_accept_fd;
	int retval;

	while(1)
				{

					ran_accept_fd = accept(ran_listen_fd, NULL, NULL);
					if(ran_accept_fd < 0)
					{
						if((errno == EAGAIN) ||
							(errno == EWOULDBLOCK))
						{
							break;
						}
						else
						{
							cout<<"Error on accept"<<endl;
							break;
						}
					}

					epevent.data.fd = ran_accept_fd;
					epevent.events = EPOLLIN | EPOLLET;
					retval = epoll_ctl( epollfd, EPOLL_CTL_ADD, ran_accept_fd, &epevent);
					if(retval == -1)
					{ 
						TRACE(cout<<"Error: Adding ran accept to epoll"<<endl;)
					}
					fddata.act = 1;
					fddata.initial_fd = 0;
					fddata.msui = 0;
					memset(fddata.buf,0,mdata_BUF_SIZE);
					fddata.buflen = 0;
					fdmap.insert(make_pair(ran_accept_fd,fddata));



				}
}

int Utils::handleEpollOut(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata, epoll_event &epevent,int case1)
{
							int err = 0;
							int retval = -1;
							int returnval;
							socklen_t len = sizeof(int);
							returnval = getsockopt(cur_fd, SOL_SOCKET, SO_ERROR, &err, &len);
							if( (returnval != -1) && (err == 0))	// Conn estd;
							{

								returnval = write_stream(cur_fd, fddata.buf, fddata.buflen);
								if(returnval < 0)
								{
									TRACE(cout<<"Error: Hss data not sent after accept"<<endl;)
									exit(-1);
								}
								if(returnval > 0)
									retval = 0;								
								epevent.data.fd = cur_fd;
								epevent.events = EPOLLIN | EPOLLET;
								returnval = epoll_ctl(epollfd, EPOLL_CTL_MOD, cur_fd, &epevent);
								if(returnval == -1)
								{
									TRACE(cout<<"Error: Adding Epoll MOD hss rcv"<<endl;)
									exit(-1);
								}

								fdmap.erase(cur_fd);
								fddata.act = case1+1;
								fddata.buflen = 0;
								memset(fddata.buf,0,mdata_BUF_SIZE);
								fdmap.insert(make_pair(cur_fd, fddata));
							}
							else
							{
								TRACE(cout<<"Error: Accept after connect Failed "<<endl;)
								exit(-1);
							}

							//retnval denotes where connect was successful or not
							return retval;
}
int make_socket_non_blocking(int fd)
{
int flags, returnvalue,s;

flags = fcntl(fd,F_GETFL,0); // gets flag
	if(flags == -1)
	{
	perror("ERROR occurred in fcntl");
	return -1;
	}
flags = flags | O_NONBLOCK;

s = fcntl(fd,F_SETFL,flags) ; // sets Nonblock flag	

if( s == -1)
{
	perror("fcntl");
	return -1;
}
return 0;

}
int read_stream(int conn_fd, uint8_t *buf, int len) 
{
	int ptr;
	int retval;
	int read_bytes;
	int remaining_bytes;

	ptr = 0;
	remaining_bytes = len;
	if (conn_fd < 0 || len <= 0) {
		return -1;
	}
	while (1) {
		read_bytes = read(conn_fd, buf + ptr, remaining_bytes);
		if (read_bytes <= 0) {
			retval = read_bytes;
			break;
		}
		ptr += read_bytes;
		remaining_bytes -= read_bytes;
		if (remaining_bytes == 0) {
			retval = len;
			break;
		}
	}
	return retval;
}
int write_stream(int conn_fd, uint8_t *buf, int len) 
{
	int ptr;
	int retval;
	int written_bytes;
	int remaining_bytes;

	ptr = 0;
	remaining_bytes = len;
	if (conn_fd < 0 || len <= 0) {
		return -1;
	}	
	while (1) {
		written_bytes = write(conn_fd, buf + ptr, remaining_bytes);
		if (written_bytes <= 0) {
			retval = written_bytes;
			break;
		}
		ptr += written_bytes;
		remaining_bytes -= written_bytes;
		if (remaining_bytes == 0) {
			retval = len;
			break;
		}
	}
	return retval;
}
