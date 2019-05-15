#ifndef LIB_H
#define LIB_H

#define _LARGEFILE64_SOURCE

#include <assert.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdint>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <ctime>
#include <pthread.h>
#include <csignal>
#include <iostream>
#include <sys/time.h>
#include <sched.h>
#include <map>
#include <unordered_map>
#include <string>
#include <bitset>
#include <boost/pool/simple_segregated_storage.hpp>  //for memory pool
#include <boost/foreach.hpp>  //for memory pool
#include <vector>  //for memory pool
#include <cstddef>  //for memory pool
#include <algorithm>  //for client_vector
#include "datastore/dspackethandler.hpp"
#include <mutex>
#include <fstream>

#define LIBVNF_STACK_KERNEL 1
#define LIBVNF_STACK_KERNEL_BYPASS 2
#define LIBVNF_STACK_KERNEL_L3 3

#if LIBVNF_STACK == LIBVNF_STACK_KERNEL

#include <sys/epoll.h>

#elif LIBVNF_STACK == LIBVNF_STACK_KERNEL_BYPASS

#include "mtcp_api.h"
#include "mtcp_epoll.h"
//#include "dpdk_api.h"
//#include "netmap_api.h"
//#include "cpu.h"
#include "debug.h"
#include "rss.h"

#elif LIBVNF_STACK == LIBVNF_STACK_KERNEL_L3

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#endif

#define MAX_EVENTS 2048
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_CACHE_LEN 20

enum event_type {
    READ = 1, ACCEPT = 2, ERROR = 3
};

enum data_location {
    LOCAL = 1, REMOTE = 2, CHECKCACHE = 3
};

typedef void (*fn)(int, void *, char *, int, int);

typedef void (*fn_ctrl)(string task, string vnf_name, string vnf_ip, string event);

using namespace std;

/**
 * @brief initializes the libvnf config parameters
 * @param _maxCores: number of cores of VM
 * @param _bufferSize: packet buffer size,
 * @param _dataStoreIP: ip of data store,
 * @param _dataStorePorts: ports of datastore,
 * @param _dataStoreThreshold: local datastore size,
 * @param _useRemoteDataStore: use local or remote datastore
 * */
int
initLibvnf(int _maxCores, int _bufferSize,
           string _dataStoreIP,
           vector<int> _dataStorePorts,
           int _dataStoreThreshold,
           bool _useRemoteDataStore);

/**
 * @brief initalize request object size and sizes of request object.
 * @param msize[]: sizes of request objects
 * @param m_tot: total number of request object sizes
 */
void
initReqPool(int msize[], int m_tot);


/**
 * @brief assign a request object to a connection
 * @param vnf_connid: connection identifier
 * @param index of request object size in array provided in initReqPool
 * */
void *
allocReqObj(int vnf_connid, int index);

/**
 * @brief free the memory of a request object
 * @param vnf_connid: connection identifier to which the request object is assigned
 * @param index: index of request object size in array provided in initReqPool
 * */
void
freeReqObj(int vnf_connid, int index);

/**
 * @brief link an existing request object to a new connection pertaining to the same request.
 * @param vnf_connid: connection identifier
 * @param *requestObj: exisitng request object
 * */
void
linkReqObj(int vnf_connid, void *requestObj);

/**
 * @brief buffer a packet on a connection
 * @param vnf_connid: connection identifier
 * @param *pkt_mem_ptr: pointer to packet in packet pool
 * */
void *
getPktDNE(int vnf_connid, void *pkt_mem_ptr);

/**
 * @brief remove the buffered packet from the packet pool
 * @param vnf_connid: connection identifier
 * @param *pkt_mem_ptr: pointer to packet in packet pool
 * */
void
unsetPktDNE(int vnf_connid, void *pkt_mem_ptr);

/**
 * @brief get a empty buffer to write packet to send
 * @param vnf_connid: connection for which buffer is needed
 * */
char *
getPktBuf(int vnf_connid);

/**
 * @brief get pointer to state in local memory
 * @param ds_key: the key for which state needs to be stored
 * */
void *
setKeyDNE(int ds_key);

/**
 * @brief remove pointer to state in local memory
 * @param ds_key: the key for which state pointer was done
 * */
void
unsetKeyDNE(int ds_key);

/**
 * @brief initialise the VNF server
 * @param inter_face: the interface to send/receive packets (neede for L3 VNF)
 * @param server_ip: IP of VNF (needed for app-layer VNF)
 * @param server_port: port of VNF (needed for app-layer VNF)
 * @param protocol: communication protocol (currently only "tcp" is supported)
 * */
int
createServer(string inter_face, string server_ip, int server_port, string protocol);

/**
 * @brief register a callback for packets received on a connection
 * @param vnf_connid: connection identifier
 * @param event_type: type of event READ or ERROR
 * @param callbackFnPtr(int vnf_connid, void * request_object, char * packet, int packet_length, int error_code)
 * */
void
registerCallback(int vnf_connid, enum event_type, void callbackFnPtr(int, void *, char *, int, int));

/**
 * @brief start the VNF
 * */
void
startEventLoop();

/**
 * @brief connect as cleint to another VNF
 * @param vnf_connid: connection identifier
 * @param local_ip: IP of current VNF
 * @param remoteServerIP: IP of VNF to which we want to connect as client
 * @param remoteServerPort: port of the other VNF
 * @param protocol: communication protocol (currently only "tcp" is supported)
 * */
int
createClient(int vnf_connid, string local_ip, string remoteServerIP, int remoteServerPort, string protocol);

/**
 * @brief send data to another VNF or client
 * @param vnf_connid: connection identifier
 * @param *packetToSend: data to be sent
 * @param size: size of data
 * */
void
sendData(int vnf_connid, char *packetToSend, int size);

/**
 * @brief store data in datastore
 * @param vnf_connid: connection identifier
 * @param table_name: name of table (can be empty string if only one table)
 * @param key: key identifier (cuurently only int value allowed)
 * @param location: where data to be stored remote or local
 * @param *value: value to be stored corresponding to the key
 * @param value_len: length of value
 * @param callbackFnPtr(int vnf_connid, void * request_object, void * value, int packet_length, int error_code) : callback function called when error occurs
 * */
void
setData(int vnf_connid, string table_name, int key, enum data_location location, void *value, int value_len,
        void callbackFnPtr(int, void *, void *, int, int));

/**
 * @brief fetch data from datastore
 * @param vnf_connid: connection identifier
 * @param table_name: name of table (can be empty string if only one table)
 * @param key: key identifier (cuurently only int value allowed)
 * @param location: where data to be stored remote or local
 * @param callbackFnPtr(int vnf_connid, void * request_object, void * value, int packet_length, int error_code) : callback function called when data is received
 * */
void
getData(int vnf_connid, string table_name, int key, enum data_location location,
        void callbackFnPtr(int, void *, void *, int, int));

/**
 * @brief delete key-value pair from datastore
 * @param vnf_connid: connection identifier
 * @param table_name: name of table (can be empty string if only one table)
 * @param key: key identifier (cuurently only int value allowed)
 * @param location: where data to be stored remote or local
 * */
void
delData(int vnf_connid, string table_name, int key, enum data_location location);

/**
 * @brief close a connection
 * @param vnf_connid: connection identifier
 * */
void
closeConn(int vnf_connid);

void
registerforNotification(string controller_ip,
                        void callbackFnPtr(string task, string vnf_name, string vnf_ip, string event));

void
handle_arp_packet(char *buffer);

#endif

