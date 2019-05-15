#ifndef LIBVNF_H
#define LIBVNF_H

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <spdlog/spdlog.h>
#include <assert.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdint>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
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
#include <boost/pool/simple_segregated_storage.hpp>
#include <boost/foreach.hpp>
#include <vector>
#include <cstddef>
#include <algorithm>
#include <mutex>
#include <fstream>

#include "datastore/dspackethandler.hpp"

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
#define NUM_CALLBACK_EVENTS 2

namespace vnf {

enum EventType {
    READ = 0, ACCEPT = 1, ERROR = 2
};

enum DataLocation {
    LOCAL = 1, REMOTE = 2, CHECKCACHE = 3
};

class ConnId {
public:
  const int coreId;
  const int socketId;

  ConnId(int coreId, int socketId) : coreId(coreId), socketId(socketId) {}

  ConnId(int value) : coreId(value), socketId(value) {}

  bool isValid() {
    return coreId > -1 || socketId > -1;
  }

  bool operator==(const ConnId& rhs) {
    return this->coreId == rhs.coreId && this->socketId == rhs.socketId;
  }

  void *
  allocReqObj(int reqObjType, int reqObjId = 0);

  ConnId&
  freeReqObj(int reqObjType, int reqObjId = 0);

  ConnId&
  linkReqObj(void *requestObj, int reqObjId = 0);

  void *
  setPktDNE(void *packet);

  ConnId&
  unsetPktDNE(void *packet);

  char *
  getPktBuf();

  ConnId&
  registerCallback(enum EventType event, void callback(ConnId& connId, int reqObjId, void * requestObject, char * packet, int packetLen, int errorCode, int streamNum));

  ConnId&
  registerReqObjIdExtractor(int roidExtractor(char *packet, int packetLen));

  ConnId&
  registerPacketBoundaryDisambiguator(vector<int> pbd(char *buffer, int bufLen));

  ConnId
  createClient(string localIP, string remoteIP, int remotePort, string protocol);

  ConnId&
  sendData(char *packetToSend, int packetSize, int streamNum = 0);

  ConnId&
  storeData(string tableName, int key, enum DataLocation location, void *value, int valueLen,
          void errorCallback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode));

  ConnId&
  retrieveData(string tableName, int key, enum DataLocation location,
          void callback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode), int reqObjId = 0);

  ConnId&
  delData(string tableName, int key, enum DataLocation location);

  void
  closeConn();

};

typedef void (*CallbackFn)(ConnId&, int, void *, char *, int, int, int);

typedef void (*DSCallbackFn)(ConnId&, int, void *, void *, int, int);

typedef void (*fn_ctrl)(string task, string vnf_name, string vnf_ip, string event);

typedef int (*ReqObjExtractorFn)(char *, int);

typedef vector<int> (*PacketBoundaryDisambiguatorFn)(char *, int);

/**
 * @brief Initializes the libvnf config parameters
 * @param maxCores: number of cores of VM
 * @param bufferSize: packet buffer size,
 * @param dataStoreIP: ip of data store,
 * @param dataStorePorts: ports of datastore,
 * @param dataStoreThreshold: local datastore size,
 * @param useRemoteDataStore: use local or remote datastore
 * @return 0 for success, appropriate error code for any failure
 * */
int
initLibvnf(int maxCores, int bufferSize,
           string dataStoreIP,
           vector<int> dataStorePorts,
           int dataStoreThreshold,
           bool useRemoteDataStore);

/**
 * @brief Initializes the libvnf config parameters
 * @param jsonFilePath: path to json file containing parameters
 * @return 0 for success, appropriate error code for any failure
 * */
/*
int
initLibvnf(const string &jsonFilePath);
*/
/**
 * @brief Initialize number of request object and their sizes
 * @param requestObjectSizes[]: size of request object of each type
 * @param numRequestObjectSizes: total number of request object types
 */
void
initReqPool(int requestObjectSizes[], int numRequestObjectSizes);

/**
 * @brief Assign a request object to a connection
 * @param connId: connection identifier
 * @param reqObjType: type of request object
 * @param reqObjId: request object identifier in set belonging to a connection id
 * @return pointer to the memory allocated for request object with id as reqObjId
 * */
void *
allocReqObj(ConnId& connId, int reqObjType, int reqObjId = 0);

/**
 * @brief Free the memory of a request object
 * @param connId: connection identifier to which the request object is assigned
 * @param reqObjType: type of request object
 * @param reqObjId: request object identifier in set belonging to a connection id
 * */
ConnId&
freeReqObj(ConnId connId, int reqObjType, int reqObjId = 0);

/**
 * @brief Link an existing request object to a new connection pertaining to the same request
 * @param connId: connection identifier
 * @param *requestObj: existing request object
 * @param reqObjId: request object identifier in set belonging to a connection id
 * */
ConnId&
linkReqObj(ConnId connId, void *requestObj, int reqObjId = 0);

/**
 * @brief Set do not evict flag on packet i.e. it is not freed right after the callback is executed
 * @param connId: connection identifier
 * @param *packet: pointer to packet in packet pool
 * @return same as packet
 * */
void *
setPktDNE(ConnId& connId, void *packet);

/**
 * @brief Remove DNE flag and remove the packet from the packet pool
 * @param connId: connection identifier
 * @param *pktMemPtr: pointer to packet in packet pool
 * */
ConnId&
unsetPktDNE(ConnId connId, void *packet);

/**
 * @brief Get a pointer newly allocated memory where packet can be written and passed to sendData. The deallocation of this memory is automatically done after packet is sent successfully.
 * @param connId: connection for which buffer is needed
 * @return pointer to newly allocated memory where packet to send can be written
 * */
char *
getPktBuf(ConnId& connId);

/**
 * @brief Tag cached key value pair of remote datastore non evictable. By doing this it is not cleared from cache until unsetCachedDSKeyDNE is called.
 * @param dsKey: the key in key value pair
 * @return pointer to the value corresponding to dsKey stored in cache is returned
 * */
void *
setCachedDSKeyDNE(int dsKey);

/**
 * @brief Tag cached key value pair of remote datastore evictable.
 * @param dsKey: the key in key value pair
 * */
void
unsetCachedDSKeyDNE(int dsKey);

/**
 * @brief Initialize the VNF as server with network parameters
 * @param _interface: the interface to send/receive packets (neede for L3 VNF)
 * @param serverIp: IP of VNF (needed for app-layer VNF)
 * @param serverPort: port of VNF (needed for app-layer VNF)
 * @param protocol: communication protocol
 * @return the connection id that can be used to register callbacks when server accepts clients
 * */
ConnId
initServer(string _interface, string serverIp, int serverPort, string protocol);

/**
 * @brief Register a callback for an event type on a connection
 * @param connId: connection identifier
 * @param event: type of event READ or ERROR
 * @param callback(ConnId& connId, void * requestObject, char * packet, int packet_length, int error_code)
 * */
ConnId&
registerCallback(ConnId& connId, enum EventType event,
                 void callback(ConnId& connId, int reqObjId, void * requestObject, char * packet, int packetLen, int errorCode, int streamNum));

/**
 * @brief Register a function to extract request object id from a packet on a connection
 * @param connId: connection identifier
 * @param roidExtractor(char * packet, int packetLen): function that extracts request object id from a given packet
 * */
ConnId&
registerReqObjIdExtractor(ConnId& connId, int roidExtractor(char *packet, int packetLen));

/**
 * @brief Register a function to return a list of packets given a network buffer
 * @param connId: connection identifier
 * @param pbd(char *buffer, int bufLen): function to return a list of packets given a network buffer
 * */
ConnId&
registerPacketBoundaryDisambiguator(ConnId& connId, vector<int> pbd(char *buffer, int bufLen));

/**
 * @brief start the network function
 * */
void
startEventLoop();

/**
 * @brief Connect as client to an IP and port using a protocol
 * @param connId: connection identifier
 * @param localIP: IP of current VNF
 * @param remoteIP: IP of VNF to which we want to connect as client
 * @param remotePort: port of the other VNF
 * @param protocol: communication protocol
 * @return the connection id that can be used to register callbacks when read or error occurs on the socket
 * */
ConnId
createClient(ConnId& connId, string localIP, string remoteIP, int remotePort, string protocol);

/**
 * @brief Send data to a network function
 * @param connId: connection identifier
 * @param *packetToSend: data to be sent
 * @param packetSize: size of data
 * @param streamNum: stream number of sctp connection if the connection is on sctp
 * */
ConnId&
sendData(ConnId& connId, char *packetToSend, int packetSize, int streamNum = 0);

/**
 * @brief Store data in datastore
 * @param connId: connection identifier
 * @param table_name: name of table (can be empty string if only one table)
 * @param key: key identifier (currently only int value allowed)
 * @param location: where data to be stored remote or local
 * @param *value: value to be stored corresponding to the key
 * @param value_len: length of value
 * @param callbackFnPtr(ConnId& connId, void * requestObject, void * value, int packet_length, int error_code) : callback function called when error occurs
 * */
ConnId&
storeData(ConnId& connId, string tableName, int key, enum DataLocation location, void *value, int valueLen,
        void errorCallback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode));

/**
 * @brief Fetch data from datastore
 * @param connId: connection identifier
 * @param tableName: name of table (can be empty string if only one table)
 * @param key: key identifier (currently only int value allowed)
 * @param location: where data to be stored remote or local
 * @param callback(ConnId& connId, void * requestObject, void * value, int packet_length, int error_code) : callback function called when data is received
 * */
ConnId&
retrieveData(ConnId& connId, string tableName, int key, enum DataLocation location,
        void callback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode), int reqObjId = 0);

/**
 * @brief Delete key-value pair from datastore
 * @param connId: connection identifier
 * @param tableName: name of table (can be empty string if only one table)
 * @param key: key identifier (currently only int value allowed)
 * @param location: where data to be stored remote or local
 * */
ConnId&
delData(ConnId& connId, string tableName, int key, enum DataLocation location);

/**
 * @brief Close a connection
 * @param connId: connection identifier
 * */
void
closeConn(ConnId& connId);

void
registerforNotification(string controller_ip,
                        void callbackFnPtr(string task, string vnf_name, string vnf_ip, string event));

void
handle_arp_packet(char *buffer);

}

#endif

