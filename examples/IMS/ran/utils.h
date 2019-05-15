#ifndef UTILS_H
#define UTILS_H

/* (C++) chrono: high_resolution_clock, microseconds */
#include <chrono>

/* (C++) cout, endl */
#include <iostream> 

/* (C) INT_MAX */
#include <limits.h>

/* (C) pthread_create, pthread_kill */
#include <pthread.h>

/* (C++) STL: queue */
#include <queue>

/* (C++) default_random_engine, exponential_distribution<T> */
#include <random>

/* (C) signal */
#include <signal.h>

/* (C) memset, memmove */
#include <stdio.h>

/* (C) strlen */
#include <string.h>

/* (C++) STL: string */
#include <string>

/* (C++) stringstream */
#include <sstream>

/* (C++) STL: thread */
#include <thread>

/* (C++) STL: unordered map */
#include <unordered_map>

/* (C++) STL: vector */
#include <vector>

/* (C++ ) Epoll */
#include <sys/epoll.h>
/* (C++ ) Map */
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define mdata_BUF_SIZE 1024


using namespace std;

typedef std::chrono::high_resolution_clock CLOCK;
typedef std::chrono::microseconds MICROSECONDS;

struct mdata{
	int act;
	int initial_fd;
	int second_fd;
	uint8_t buf[mdata_BUF_SIZE];
	int buflen;
	uint32_t msui;
	int sipheader;
	int privateidentity;
};


#define DEBUG 0
#define TRACE(x) if (DEBUG) { x }

const int MAX_UE_COUNT = 10000;

class Utils {
public:
	void handle_type1_error(int, string);
	void handle_type2_error(int, string);
	char* allocate_str_mem(int);
	uint8_t* allocate_uint8_mem(int);
	void time_check(time_t, double, bool&);
	int max_ele(vector<int> inp);
	int HandleIncomingSocket( int epollfd, int ran_listen_fd, epoll_event &epevent, map<int, mdata> &fdmap, mdata &fddata);
	int handleEpollOut(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata, epoll_event &epevent,int case1);

};

extern Utils g_utils;

int make_socket_non_blocking(int fd);
int read_stream(int conn_fd, uint8_t *buf, int len) ;
int write_stream(int conn_fd, uint8_t *buf, int len) ;


#endif /* UTILS_H */
