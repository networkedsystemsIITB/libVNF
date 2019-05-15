//#include "json.hpp"
#include "core.hpp"
#include "utils.hpp"

using namespace vnf;
using namespace std;

PerCoreState *perCoreStates;

Globals globals;

UserConfig *userConfig = nullptr;

int vnf::initLibvnf(int maxCores, int bufferSize, string dataStoreIP, vector<int> dataStorePorts, int dataStoreThreshold,
               bool useRemoteDataStore) {
    userConfig = new UserConfig(maxCores, bufferSize,
                                dataStoreIP, dataStorePorts,
                                dataStoreThreshold, useRemoteDataStore);
    perCoreStates = new PerCoreState[userConfig->MAX_CORES];
    return 0;
}
/*
int vnf::initLibvnf(const string &jsonFilePath) {
    std::ifstream jsonFileInputStream(jsonFilePath);
    nlohmann::json json;
    jsonFileInputStream >> json;

    return initLibvnf(json["maxCores"].get<int>(),
                      json["bufferSize"].get<int>(),
                      json["dataStoreIP"].get<string>(),
                      json["dataStorePorts"].get<vector<int> >(),
                      json["dataStoreThreshold"].get<int>(),
                      json["useRemoteDataStore"].get<bool>());
}
*/
void vnf::initReqPool(int requestObjectSizes[], int numRequestObjectSizes) {
    if (numRequestObjectSizes > MAX_REQUEST_OBJECT_TYPES) {
        // todo: error handling
        spdlog::error("Maximum {} types of request objects are allowed", MAX_REQUEST_OBJECT_TYPES);
        return;
    }

    spdlog::info("Number of request object types requested: {}", numRequestObjectSizes);

    int sizesInPowersOf2[numRequestObjectSizes];
    for (int i = 0; i < numRequestObjectSizes; i++) {
        if (requestObjectSizes[i] && !(requestObjectSizes[i] & (requestObjectSizes[i] - 1))) {
            // requestObjectSizes[i] is a non-negative power of 2
            sizesInPowersOf2[i] = requestObjectSizes[i];
        } else {
            int sizeInPowersOf2 = 1; // starting from 2^0
            while (sizeInPowersOf2 < requestObjectSizes[i]) {
                sizeInPowersOf2 <<= 1;
            }
            sizesInPowersOf2[i] = sizeInPowersOf2;
        }
        spdlog::info("Request object type {} is of {} bytes", i + 1, sizesInPowersOf2[i]);
    }

    for (int coreId = 0; coreId < userConfig->MAX_CORES; coreId++) {
        for (int reqObjType = 0; reqObjType < numRequestObjectSizes; reqObjType++) {
            perCoreStates[coreId].reqObjSizesInPowersOf2[reqObjType] = sizesInPowersOf2[reqObjType];
        }
    }
}

// free memory from data store pool when threshold reached. remove cached entry without the dne bit set
void freeDSPool() {
    for (auto &it : cache_void_list) {
        if (globals.canEvictCachedDSKey(it.first)) {
            globals.cachedRemoteDatastore.erase(it.second);
            globals.localDatastore.erase(it.second);
            globals.localDatastoreLens.erase(it.second);
            globals.dsMemPoolManager.free(it.first);
        }
    }
    cache_void_list.clear();
    globals.dsSize = 0;
}

int createClientToDS(int coreId, string remoteIP, int remotePort) {
    int socketId = socket(AF_INET, SOCK_STREAM, 0);
    if (socketId < 0) {
        spdlog::error("Failed to create listening socket!");
        return -1;
    }
    makeSocketNonBlocking(socketId);

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP.c_str());
    address.sin_port = htons(remotePort);

    int ret = connect(socketId, (struct sockaddr *) &address, sizeof(struct sockaddr_in));
    if (ret < 0 && errno != EINPROGRESS) {
        spdlog::error("Connect issue {}", errno);
        close(socketId);
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = socketId;
    int epFd = perCoreStates[coreId].epollFd;
    epoll_ctl(epFd, EPOLL_CTL_ADD, socketId, &ev);

    return socketId;
}

void *serverThread(void *args) {
    struct ServerPThreadArgument argument = *((struct ServerPThreadArgument *) args);
    int coreId = argument.coreId;
    spdlog::info("Server thread started on core {}", coreId);

    // memory pool initialization for request objects
    for (int reqObjType = 0; reqObjType < MAX_REQUEST_OBJECT_TYPES; ++reqObjType) {
        perCoreStates[coreId].initMemPoolOfRequestObject(reqObjType);
    }

    // memory pool initialization for packets
    spdlog::info("Packets Memory Pool Size: {}", perCoreStates[coreId].packetMemPoolBlock.size());
    perCoreStates[coreId].packetsMemPoolManager.add_block(
            &perCoreStates[coreId].packetMemPoolBlock.front(),
            perCoreStates[coreId].packetMemPoolBlock.size(),
            1024);

    int epFd = epoll_create(MAX_EVENTS + 5);
    if (epFd < 0) {
        spdlog::error("Failed to create epoll descriptor!");
        return nullptr;
    }
    globals.epollArrayLock.lock();
    perCoreStates[coreId].epollFd = epFd;
    globals.epollArrayLock.unlock();

    struct epoll_event ev;
    globals.listenLock.lock();
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = globals.listeningSocketFd;
    epoll_ctl(epFd, EPOLL_CTL_ADD, globals.listeningSocketFd, &ev);
    globals.listenLock.unlock();

    struct epoll_event *epollEvents;
    epollEvents = (struct epoll_event *) calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if (!epollEvents) {
        spdlog::error("Failed to create epoll event struct");
        exit(-1);
    }
    spdlog::info("Waiting for epollEvents");

    bool _useRemoteDataStore = userConfig->USE_REMOTE_DATASTORE;
    while (!perCoreStates[coreId].isJobDone) {
        // connect to remote data store for first time
        if (_useRemoteDataStore) {
            _useRemoteDataStore = false;
            if (coreId == 0) {
                perCoreStates[coreId].dsSocketId1 = createClientToDS(coreId, userConfig->DATASTORE_IP, userConfig->DATASTORE_PORTS[0]);
                perCoreStates[coreId].dsSocketId2 = createClientToDS(coreId, userConfig->DATASTORE_IP, userConfig->DATASTORE_PORTS[1]);
            } else {
                perCoreStates[coreId].dsSocketId1 = createClientToDS(coreId, userConfig->DATASTORE_IP, userConfig->DATASTORE_PORTS[2]);
                perCoreStates[coreId].dsSocketId2 = createClientToDS(coreId, userConfig->DATASTORE_IP, userConfig->DATASTORE_PORTS[3]);
            }
        }

        // wait for epoll events
        int numEventsCaptured = epoll_wait(epFd, epollEvents, MAX_EVENTS, -1);
        if (numEventsCaptured < 0) {
            if (errno != EINTR) {
                perror("epoll_wait");
            }
            break;
        }
        for (int i = 0; i < numEventsCaptured; i++) {
            int currentSocketId = epollEvents[i].data.fd;
            uint32_t currentEvents = epollEvents[i].events;

            /* EPOLLERR: Error  condition  happened  on  the associated file descriptor.  This event is also reported for the write end of a pipe when the read end has been closed. EPOLLRDHUP (since Linux 2.6.17): Stream socket peer closed connection, or shut down writing half of connection. (This flag is especially useful for writing simple code to detect peer shutdown when using Edge Triggered monitoring.) */
            if ((currentEvents & EPOLLERR) || (currentEvents & EPOLLRDHUP)) {
                //spdlog::error("EPOLLERR or EPOLLRDHUP. Clearing pending data queue and closing socket fd");
                if (currentSocketId == globals.listeningSocketFd) {
                    spdlog::error("Oh Oh, lsfd it is");
                    exit(-1);
                }
                while (!perCoreStates[coreId].isPendingDataQueueEmpty(currentSocketId)) {
                    PendingData dataToSend = perCoreStates[coreId].socketIdPendingDataQueueMap[currentSocketId].front();
                    perCoreStates[coreId].packetsMemPoolManager.free((void *) dataToSend.data);
                    perCoreStates[coreId].socketIdPendingDataQueueMap[currentSocketId].pop();
                }
                close(currentSocketId);

                continue;
            }

            /* Event occured on global listening socket. Therefore accept the connection */
            if (currentSocketId == globals.listeningSocketFd) {

                while (true) {
                    int socketId = accept(globals.listeningSocketFd, NULL, NULL);
                    if (socketId < 0) {
                        // Need lsfd non blocking to run this!!!!!!
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            spdlog::error("Error on accept");
                        }
                        break;
                    }
                    if(globals.serverProtocol == "sctp"){
                        struct sctp_initmsg s_initmsg;
                        memset(&s_initmsg, 0, sizeof (s_initmsg));
                        s_initmsg.sinit_num_ostreams = 8;
                        s_initmsg.sinit_max_instreams = 8;
                        s_initmsg.sinit_max_attempts = 8;
                        if(setsockopt(socketId, IPPROTO_SCTP, SCTP_INITMSG, &s_initmsg, sizeof (s_initmsg)) < 0){
                            spdlog::error("Socket option for sctp_init error");
                            exit(-1);
                        }
                        struct sctp_event_subscribe events;
                        memset((void *) &events, 0, sizeof(events));
                        events.sctp_data_io_event = 1;
                        if(setsockopt( socketId, SOL_SCTP, SCTP_EVENTS, (const void *)&events, sizeof(events)) < 0){
                            spdlog::error("Socket option for sctp_events error");
                            exit(-1);
                        }
                    }
                    makeSocketNonBlocking(socketId);
                    ev.events = EPOLLIN;
                    ev.data.fd = socketId;
                    epoll_ctl(epFd, EPOLL_CTL_ADD, socketId, &ev);

                    perCoreStates[coreId].socketProtocolMap[socketId] = globals.serverProtocol;
                    perCoreStates[coreId].connCounter++;
                    for (int eventType = 0; eventType < NUM_CALLBACK_EVENTS; ++eventType) {
                        perCoreStates[coreId].socketIdCallbackMap[eventType][socketId] = argument.onAcceptByServerCallback[eventType];
                    }
                    perCoreStates[coreId].socketIdDSCallbackMap[socketId] = argument.onAcceptByServerDSCallback;
                    perCoreStates[coreId].socketIdReqObjIdExtractorMap[socketId] = argument.onAcceptByServerReqObjIdExtractor;
                    perCoreStates[coreId].socketIdPBDMap[socketId] = argument.onAcceptByServerPBD;
                    CallbackFn callback = perCoreStates[coreId].socketIdCallbackMap[ACCEPT][socketId];
                    ConnId connId = ConnId(coreId, socketId);
                    if(callback){
                        callback(connId, 0, nullptr, nullptr, 0, 0, 0);
                    }
                }

                continue;
            }

            /* EPOLLIN: The associated file is available for read(2) operations. */
            if (currentEvents & EPOLLIN) {
                /* Current socketId points to remote datastore */
                if (perCoreStates[coreId].isDatastoreSocket(currentSocketId)) {
                    /* TODO: fix this shit */
                    while (true) {
                        DSPacketHandler pkt;
                        int pkt_len, retval;
                        pkt.clear_pkt();
                        retval = readFromStream(currentSocketId, pkt.data, sizeof(int));
                        if (retval < 0) {
                            if (errno == EAGAIN) {
                                break;
                            }
                        } else {
                            perCoreStates[coreId].numPacketsRecvFromDs++;
                            memmove(&pkt_len, pkt.data, sizeof(int) * sizeof(uint8_t));
                            pkt.clear_pkt();
                            retval = readFromStream(currentSocketId, pkt.data, pkt_len);
                            pkt.data_ptr = 0;
                            pkt.len = retval;
                            if (retval < 0) {
                                spdlog::error("Error: Packet from HSS Corrupt, break");
                                break;
                            }
                        }
                        int socketId, bufKey;
                        string buffer;
                        pkt.extract_item(socketId);
                        pkt.extract_item(bufKey);
                        pkt.extract_item(buffer);
                        buffer += '\0';

                        void *dsMalloc;
                        globals.dataStoreLock.lock();
                        if (globals.dsSize == userConfig->DATASTORE_THRESHOLD) {
                            freeDSPool();
                        }
                        // cache the state
                        dsMalloc = globals.dsMemPoolManager.malloc();
                        globals.dsSize++;
                        memcpy(dsMalloc, buffer.c_str(), buffer.length());
                        globals.localDatastore[bufKey] = dsMalloc;
                        globals.localDatastoreLens[bufKey] = buffer.length();
                        globals.cachedRemoteDatastore[bufKey] = dsMalloc;
                        cache_void_list[dsMalloc] = bufKey;
                        globals.dataStoreLock.unlock();

                        ConnId connId = ConnId(coreId, socketId);

                        // request object id extractor from packet
                        ReqObjExtractorFn extractor = perCoreStates[coreId].socketIdReqObjIdExtractorMap[socketId];
                        int reqObjId = extractor == nullptr ? 0 : extractor(const_cast<char *>(buffer.c_str()), 0); // fix me : replace 0 packetlen with actual packet len
                        cout.flush();

                        // callback
                        DSCallbackFn callback = perCoreStates[coreId].socketIdDSCallbackMap[socketId];
                        callback(connId, reqObjId,
                                 perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId],
                                 (void *) buffer.c_str(),
                                 userConfig->BUFFER_SIZE, 0);
                    }

                    continue;
                }

                /* Current socketId points to non-remote datastore network function */
                int socketId = currentSocketId;
                char buffer[userConfig->BUFFER_SIZE];
                int numBytesRead;
                string currentProtocol = perCoreStates[coreId].socketProtocolMap[socketId];
                int streamNum = -1;
                /* read from socket as per the protocol specified */
                if(currentProtocol=="sctp"){
                    struct sctp_sndrcvinfo s_sndrcvinfo;
                    numBytesRead = (int) sctp_recvmsg(socketId, buffer, (size_t)userConfig->BUFFER_SIZE, (struct sockaddr *) NULL, 0, &s_sndrcvinfo, NULL);
                    streamNum = s_sndrcvinfo.sinfo_stream;
                }
                else{
                    numBytesRead = (int) read(socketId, buffer, (size_t) userConfig->BUFFER_SIZE);
                }

                /* numBytesRead == -1 for errors & numBytesRead == 0 for EOF */
                if (numBytesRead <= 0) {
                    spdlog::error("Read error on non-remote datastore socket. Trying to close the socket");
                    if (close(socketId) < 0) {
                        spdlog::error("Connection could not be closed properly");
                    }
                    continue;
                }

                perCoreStates[coreId].numRecvs++;

                /* packet boundary disambiguation */
                string prependedBuffer = perCoreStates[coreId].getLeftOverPacketFragment(socketId);
                for (int j = 0; j < numBytesRead; j++) {
                    prependedBuffer.append(1, buffer[j]);
                }
                vector<int> packetLengths(1, numBytesRead);
                PacketBoundaryDisambiguatorFn pbd = perCoreStates[coreId].socketIdPBDMap[socketId];
                if (pbd != nullptr) {
                    packetLengths = pbd((char *) prependedBuffer.c_str(), prependedBuffer.size());
                }

                int packetStart = 0;
                ConnId connId = ConnId(coreId, socketId);
                for (int packetLength : packetLengths) {
                    /* allocate heap and put current packet copy there for user to use */
                    void *packet = perCoreStates[coreId].packetsMemPoolManager.malloc();
                    string currentPacket = prependedBuffer.substr((uint) packetStart, (uint) packetLength);
                    memcpy(packet, currentPacket.c_str(), (size_t) (packetLength));

                    /* request object id extraction from packet */
                    ReqObjExtractorFn extractor = perCoreStates[coreId].socketIdReqObjIdExtractorMap[socketId];
                    int reqObjId = extractor == nullptr ? 0 : extractor((char *) packet, packetLength);
                    cout.flush();

                    /* user-defined on read callback function */
                    CallbackFn callback = perCoreStates[coreId].socketIdCallbackMap[READ][socketId];
                    void *reqObj = perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId];
                    callback(connId, reqObjId, reqObj, (char *) packet, packetLength, 0, streamNum);
                    packetStart += packetLength;

                    /* free heap previously allocated for packet if evicatable */
                    if (perCoreStates[coreId].canEvictPacket(packet)) {
                        perCoreStates[coreId].packetsMemPoolManager.free(packet);
                    }
                }

                // finally store the left over part in buffer
                perCoreStates[coreId].setLeftOverPacketFragment(socketId, prependedBuffer.substr((uint) packetStart, prependedBuffer.size() - packetStart));

                continue;
            }

            /* EPOLLOUT: The associated file is available for write(2) operations. */
            if (currentEvents & EPOLLOUT) {
                int socketId = currentSocketId;
                while (!perCoreStates[coreId].isPendingDataQueueEmpty(socketId)) {
                    PendingData dataToSend = perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].front();
                    int ret;
                    if(globals.serverProtocol == "sctp"){
                        ret = sctp_sendmsg(socketId, (void *) dataToSend.data, (size_t)dataToSend.dataLen, NULL, 0, 0, 0, dataToSend.streamNum, 0, 0);
                    } else {
                        ret = write(socketId, dataToSend.data, dataToSend.dataLen);
                    }
                    perCoreStates[coreId].packetsMemPoolManager.free((void *) dataToSend.data);
                    perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].pop();
                    if (ret < 0) {
                        spdlog::error("Connection closed with client");
                        close(socketId);
                        break;
                    }
                }

                continue;
            }
        }
    }

    return NULL;
}

void* vnf::ConnId::allocReqObj(int reqObjType, int reqObjId) {
    int coreId = this->coreId;
    int socketId = this->socketId;
    int ret = perCoreStates[coreId].mallocReqObj(socketId, reqObjType - 1, reqObjId);
    if (ret) {
        spdlog::error("Could not allocate request object on ConnId(coreId, socketId): ({}, {})", this->coreId, this->socketId);
    }
    return perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId];
}

ConnId& vnf::ConnId::freeReqObj(int reqObjType, int reqObjId) {
    int coreId = this->coreId;
    int socketId = this->socketId;
    if (perCoreStates[coreId].isARequestObjectAllocator(socketId, reqObjId)) {
        perCoreStates[coreId].freeReqObj(socketId, reqObjType - 1, reqObjId);
    } else {
        perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId].erase(reqObjId);
        if (perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId].empty()) {
            perCoreStates[coreId].socketIdReqObjIdToReqObjMap.erase(socketId);
        }
    }

    return *this;
}

ConnId& vnf::ConnId::linkReqObj(void *requestObj, int reqObjId) {
    int coreId = this->coreId;
    int socketId = this->socketId;
    perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId] = requestObj;

    return *this;
}

void* vnf::ConnId::setPktDNE(void *packet) {
    int coreId = this->coreId;
    perCoreStates[coreId].tagPacketNonEvictable(packet);
    return packet; // fixme
}

ConnId& vnf::ConnId::unsetPktDNE(void *packet) {
    int coreId = this->coreId;
    perCoreStates[coreId].packetsMemPoolManager.free(packet);
    perCoreStates[coreId].tagPacketEvictable(packet);

    return *this;
}

char* vnf::ConnId::getPktBuf() {
    int coreId = this->coreId;
    char *buffer = static_cast<char *>(perCoreStates[coreId].packetsMemPoolManager.malloc());
    return buffer;
}

void* vnf::setCachedDSKeyDNE(int dsKey) {
    /* TODO: fix this */
    void *value;

    globals.dataStoreLock.lock();
    globals.doNotEvictCachedDSValueKeyMap[globals.localDatastore[dsKey]] = dsKey;
    value = globals.localDatastore[dsKey];
    globals.dataStoreLock.unlock();

    return value; // fixme
}

void vnf::unsetCachedDSKeyDNE(int dsKey) {
    /* TODO: fix this */
    globals.dataStoreLock.lock();
    globals.doNotEvictCachedDSValueKeyMap.erase(globals.localDatastore[dsKey]);
    globals.dataStoreLock.unlock();
}

ConnId vnf::initServer(string iface, string serverIp, int serverPort, string protocol) {
    assert(userConfig != nullptr);
    signal(SIGPIPE, SIG_IGN);
    globals.serverIp = serverIp;
    globals.serverPort = serverPort;
    globals.serverProtocol = protocol;
    spdlog::info("Server initialized with IP: {} and port {}", serverIp, serverPort);
    return FIRST_TIME_CONN_ID;
}

ConnId& vnf::ConnId::registerCallback(enum EventType eventType, void callback(ConnId&, int, void *, char *, int, int, int)) {
    if (*this == FIRST_TIME_CONN_ID) {
        globals.onAcceptByServerCallback[eventType] = callback;
    } else {
        int coreId = this->coreId;
        int socketId = this->socketId;
        if (eventType == ERROR) {
            perCoreStates[coreId].socketIdErrorCallbackMap[socketId] = callback;
        } else {
            perCoreStates[coreId].socketIdCallbackMap[eventType][socketId] = callback;
        }
    }

    return *this;
}

ConnId& vnf::ConnId::registerReqObjIdExtractor(int roidExtractor(char * packet, int packetLen)) {
    if (*this == FIRST_TIME_CONN_ID) {
        globals.onAcceptByServerReqObjIdExtractor = roidExtractor;
    } else {
        int coreId = this->coreId;
        int socketId = this->socketId;
        perCoreStates[coreId].socketIdReqObjIdExtractorMap[socketId] = roidExtractor;
    }

    return *this;
}

ConnId& vnf::ConnId::registerPacketBoundaryDisambiguator(vector<int> pbd(char *buffer, int bufLen)) {
    if (*this == FIRST_TIME_CONN_ID) {
        globals.onAcceptByServerPBD = pbd;
    } else {
        int coreId = this->coreId;
        int socketId = this->socketId;
        perCoreStates[coreId].socketIdPBDMap[socketId] = pbd;
    }

    return *this;
}

void sigINTHandler(int signalCode) {
    for (int i = 0; i < userConfig->MAX_CORES; i++) {
        spdlog::info("\nOn Core: {}\n\tNo. Accepted Connections: {}\n\tNo. Packets Recv: {}\n\tNo. Packets Sent: {}\n", i, perCoreStates[i].connCounter, perCoreStates[i].numRecvs, perCoreStates[i].numSends);
        close(perCoreStates[i].dsSocketId1);
        close(perCoreStates[i].dsSocketId2);
        perCoreStates[i].isJobDone = true;
    }
    fflush(stdout);
    exit(signalCode);
}

void vnf::startEventLoop() {
    spdlog::info("Event loop is started");

    signal(SIGINT, sigINTHandler);

    if(globals.serverProtocol == "sctp"){
        globals.listeningSocketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    }
    else{
        globals.listeningSocketFd = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (globals.listeningSocketFd < 0) {
        spdlog::error("Failed to create listening socket!");
        return;
    }

    int ret = makeSocketNonBlocking(globals.listeningSocketFd);
    if (ret < 0) {
        spdlog::error("Failed to set socket in non-blocking mode.");
        return;
    }
//    globals.socketProtocolMap[globals.listeningSocketFd] = globals.serverProtocol;

    struct sockaddr_in socketAddrIn;
    socketAddrIn.sin_family = AF_INET;
    socketAddrIn.sin_addr.s_addr = inet_addr(globals.serverIp.c_str());
    socketAddrIn.sin_port = htons(globals.serverPort);

    ret = bind(globals.listeningSocketFd, (struct sockaddr *) &socketAddrIn, sizeof(struct sockaddr_in));
    if (ret < 0) {
        spdlog::error("Failed to bind to the listening socket! ");
        return;
    }

    if(globals.serverProtocol == "sctp"){
        struct sctp_initmsg s_initmsg;
        memset (&s_initmsg, 0, sizeof (s_initmsg));
        s_initmsg.sinit_num_ostreams = 8;
        s_initmsg.sinit_max_instreams = 8;
        s_initmsg.sinit_max_attempts = 8;
        if(setsockopt (globals.listeningSocketFd, IPPROTO_SCTP, SCTP_INITMSG, &s_initmsg, sizeof (s_initmsg))<0){
            spdlog::error("Socket option error sctp");
            return;
        }
        struct sctp_event_subscribe events;
        memset( (void *)&events, 0, sizeof(events) );
        events.sctp_data_io_event = 1;
        if(setsockopt( globals.listeningSocketFd, SOL_SCTP, SCTP_EVENTS, (const void *)&events, sizeof(events))<0){
            spdlog::error("Socket option for sctp_events error");
            exit(-1);
        }
    }

    ret = listen(globals.listeningSocketFd, 4096);
    if (ret < 0) {
        spdlog::error("Listen failed!");
        return;
    }
    spdlog::info("Listen on global socket successful");

    spdlog::info("Datastore Memory Pool Size: {}", globals.dsMemPoolBlock.size());
    globals.dataStoreLock.lock();
    globals.dsMemPoolManager.add_block(&globals.dsMemPoolBlock.front(), globals.dsMemPoolBlock.size(), 256);
    globals.dataStoreLock.unlock();

    auto *servers = new pthread_t[userConfig->MAX_CORES];
    auto *arguments = new struct ServerPThreadArgument[userConfig->MAX_CORES];
    for (int ithCore = 0; ithCore < userConfig->MAX_CORES; ithCore++) {
        arguments[ithCore].set(ithCore, globals.serverIp, globals.serverPort, globals.onAcceptByServerCallback,
                               globals.onAcceptByServerDSCallback,
                               globals.onAcceptByServerReqObjIdExtractor,
                               globals.onAcceptByServerPBD);

        // todo start client only after all threads have started or it would clear actual sockid mappings
        pthread_create(&servers[ithCore], NULL, serverThread, &arguments[ithCore]);
    }

    for (int i = 0; i < userConfig->MAX_CORES; i++) {
        pthread_join(servers[i], NULL);
    }
}

ConnId vnf::ConnId::createClient(string localIP, string remoteIP, int remotePort, string protocol) {
    int sockId;
    if(protocol == "sctp"){
        sockId = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        struct sctp_initmsg s_initmsg;
        memset (&s_initmsg, 0, sizeof (s_initmsg));
        s_initmsg.sinit_num_ostreams = 8;
        s_initmsg.sinit_max_instreams = 8;
        s_initmsg.sinit_max_attempts = 8;
        if(setsockopt (sockId, IPPROTO_SCTP, SCTP_INITMSG, &s_initmsg, sizeof (s_initmsg))<0){
            spdlog::error("Socket option error sctp");
            return ConnId(-1);
        }
        struct sctp_event_subscribe events;
        memset( (void *)&events, 0, sizeof(events) );
        events.sctp_data_io_event = 1;
        if(setsockopt( sockId, SOL_SCTP, SCTP_EVENTS, (const void *)&events, sizeof(events))<0){
            spdlog::error("Socket option for sctp_events error");
            exit(-1);
        }
    }
    else{
        sockId = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (sockId < 0) {
        spdlog::error("Failed to create listening socket! {}", errno);
        return ConnId(-1);
    }

    int coreId = this->coreId;
    int ret = makeSocketNonBlocking(sockId);
    perCoreStates[coreId].socketProtocolMap[sockId] = protocol;
    if (ret < 0) {
        spdlog::error("Failed to set socket in nonblocking mode.");
        return ConnId(-1);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(remoteIP.c_str());
    address.sin_port = htons(remotePort);

    ret = connect(sockId, (struct sockaddr *) &address, sizeof(struct sockaddr_in));
    if (ret < 0 && errno != EINPROGRESS) {
        spdlog::error("connect issue {}", errno);
        close(sockId);
        return ConnId(-1);
    }

    struct epoll_event epollEvent;
    epollEvent.events = EPOLLIN | EPOLLOUT;
    epollEvent.data.fd = sockId;
//    int coreId = this->coreId;
    int epFd = perCoreStates[coreId].epollFd;
    epoll_ctl(epFd, EPOLL_CTL_ADD, sockId, &epollEvent);

    return ConnId(coreId, sockId);
}

ConnId& vnf::ConnId::sendData(char *data, int dataLen, int streamNum) {
    int coreId = this->coreId;
    int socketId = this->socketId;

    // TODO: learn why this check is made
    if (socketId == -1) {
        spdlog::error("SocketId issue");
        exit(-1);
    }

    if (!perCoreStates[coreId].isPendingDataQueueEmpty(socketId)) {
        PendingData dataToSend(data, dataLen);
        perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].push(dataToSend);
        spdlog::warn("sendData: adding packet to queue as queue is already not empty");
        return *this;
    }

    int ret;
    string currentProtocol = perCoreStates[coreId].socketProtocolMap[socketId];
    if(currentProtocol == "sctp"){
        ret = sctp_sendmsg(socketId, (void *) data, (size_t) dataLen, NULL, 0, 0, 0, streamNum, 0, 0);
    } else {
        ret = write(socketId, data, dataLen);
    }
    int errnoLocal = errno;

    if (ret < 0) {
        if (errnoLocal == EAGAIN || errnoLocal == 32) {
            PendingData dataToSend(data, dataLen, streamNum);
            perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].push(dataToSend);
            spdlog::warn("sendData: adding packet to queue, not sent successfully");
        } else {
            spdlog::error("sendData: error on write {}", errnoLocal);
        }
        return *this;
    }

    if (ret != dataLen) {
        PendingData dataToSend(data, dataLen, streamNum);
        perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].push(dataToSend);
        spdlog::warn("sendData: packet complete not sent, added it to pendingDataQueue");
        return *this;
    }

    if (perCoreStates[coreId].isDatastoreSocket(socketId)) {
        perCoreStates[coreId].numPacketsSentToDs++;
    } else {
        perCoreStates[coreId].packetsMemPoolManager.free((void *) data);
    }

    perCoreStates[coreId].numSends++;

    return *this;
}

void registerDSCallback(ConnId& connId, enum EventType eventType, void callback(ConnId&, int, void *, void *, int, int)) {
    if (connId == FIRST_TIME_CONN_ID) {
        globals.onAcceptByServerDSCallback = callback;
    } else {
        int coreId = connId.coreId;
        int socketId = connId.socketId;
        if (eventType == ERROR) {
            perCoreStates[coreId].socketIdDSErrorCallbackMap[socketId] = callback;
        } else {
            perCoreStates[coreId].socketIdDSCallbackMap[socketId] = callback;
        }
    }
}

ConnId& vnf::ConnId::storeData(string tableName, int key, enum DataLocation location, void *value, int valueLen, void errorCallback(ConnId&, int, void *, void *, int, int)) {
    if (errorCallback != nullptr) {
        // todo call this somewhere
        registerDSCallback(*this, ERROR, errorCallback);
    }

    if (location == REMOTE) {
        /* TODO: fix this shit */
        int coreId = this->coreId;
        int socketId = this->socketId;
        char *s2;

        globals.dataStoreLock.lock();

        if (globals.dsSize == userConfig->DATASTORE_THRESHOLD) {
            freeDSPool();
        }

        /* TODO: Check in cache before allocating */
        /* TODO: Why same dsMemPoolManager for both cache and localDs */
        void *dsMalloc = globals.dsMemPoolManager.malloc();
        globals.dsSize++;
        memcpy(dsMalloc, value, static_cast<size_t>(valueLen) + 1);
        /* TODO: check if these lines can be commented */
        /* globals.localDatastore[key] = dsMalloc; */
        /* globals.localDatastoreLens[key] = valueLen; */
        globals.cachedRemoteDatastore[key] = dsMalloc;
        cache_void_list[dsMalloc] = key;

        globals.dataStoreLock.unlock();

        string snd_cmd = "set", snd_table = "abc", snd_value = "xyz";
        DSPacketHandler packetHandler;
        packetHandler.clear_pkt();
        packetHandler.append_item(socketId);
        packetHandler.append_item(snd_cmd);
        packetHandler.append_item(snd_table);
        packetHandler.append_item(key);
        s2 = (char *) (value);
        string s3(s2);
        packetHandler.append_item(s3);
        packetHandler.prepend_len();

        if (perCoreStates[coreId].dsSockIdSetLooper == 0) {
            ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId1);
            dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
            perCoreStates[coreId].dsSockIdSetLooper = 1;
        } else {
            ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId2);
            dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
            perCoreStates[coreId].dsSockIdSetLooper = 0;
        }

        return *this;
    }

    if (location == LOCAL) {
        globals.dataStoreLock.lock();

        if (globals.dsSize == userConfig->DATASTORE_THRESHOLD) {
            freeDSPool();
        }

        void *dsMalloc;
        if (globals.keyExistsInLocalDatastore(key)) {
            dsMalloc = globals.localDatastore[key];
        } else {
            dsMalloc = globals.dsMemPoolManager.malloc();
            globals.dsSize++;
        }
        memcpy(dsMalloc, value, static_cast<size_t>(valueLen) + 1);
        globals.localDatastore[key] = dsMalloc;
        globals.localDatastoreLens[key] = valueLen;

        globals.dataStoreLock.unlock();

        return *this;
    }

    spdlog::warn("storeData: Unknown location used {}", location);

    return *this;
}

ConnId& vnf::ConnId::retrieveData(string tableName, int key, enum DataLocation location, void callback(ConnId&, int, void *, void *, int, int), int reqObjId) {
    int coreId = this->coreId;
    int socketId = this->socketId;

    /* TODO: fix this shit */
    // if checkcache option retrieve from cache if entry exists else fetch from remote store
    // store the callback to be called after value retrieved
    if (location == CHECKCACHE) {
        // todo check this
        registerDSCallback(*this, READ, callback);
        bool isInCache = false;

        globals.dataStoreLock.lock();
        isInCache = globals.keyExistsInCachedRemoteDatastore(key);
        globals.dataStoreLock.unlock();

        if (isInCache) {
            char *packet = static_cast<char *>(globals.cachedRemoteDatastore[key]);
            // callback
            callback(*this, reqObjId,
                     perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId],
                     packet, userConfig->BUFFER_SIZE, 0);
        } else {
            string sndCmd = "get", sndTable = "abc", sndValue = "xyz";
            DSPacketHandler packetHandler;
            packetHandler.clear_pkt();
            sndCmd = "get";
            packetHandler.append_item(socketId);
            packetHandler.append_item(sndCmd);
            packetHandler.append_item(sndTable);
            packetHandler.append_item(key);
            packetHandler.prepend_len();

            if (perCoreStates[coreId].dsSockIdGetLooper == 0) {
                ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId1);
                dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
                perCoreStates[coreId].dsSockIdGetLooper = 1;
            } else {
                ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId2);
                dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
                perCoreStates[coreId].dsSockIdGetLooper = 0;
            }
            // todo check this
        }

        return *this;
    }

    if (location == REMOTE) {
        // todo check this
        registerDSCallback(*this, READ, callback);

        string sndCmd = "get", sndTable = "abc", sndValue = "xyz";
        DSPacketHandler packetHandler;
        packetHandler.clear_pkt();
        packetHandler.append_item(socketId);
        packetHandler.append_item(sndCmd);
        packetHandler.append_item(sndTable);
        packetHandler.append_item(key);
        packetHandler.prepend_len();

        if (perCoreStates[coreId].dsSockIdGetLooper == 0) {
            ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId1);
            dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
            perCoreStates[coreId].dsSockIdGetLooper = 1;
        } else {
            ConnId dsConnId = ConnId(coreId, perCoreStates[coreId].dsSocketId2);
            dsConnId.sendData((char *) packetHandler.data, packetHandler.len);
            perCoreStates[coreId].dsSockIdGetLooper = 0;
        }
        // todo check this

        return *this;
    }

    if (location == LOCAL) {
        globals.dataStoreLock.lock();

        int packetLen = globals.localDatastoreLens[key];
        char *value = (char *) (globals.localDatastore[key]);

        char valueCopy[packetLen + 1];
        for (int i = 0; i < packetLen; ++i) {
            valueCopy[i] = value[i];
        }
        valueCopy[packetLen] = 0;

        globals.dataStoreLock.unlock();

        callback(*this, reqObjId, perCoreStates[coreId].socketIdReqObjIdToReqObjMap[socketId][reqObjId], valueCopy, userConfig->BUFFER_SIZE, 0);
        return *this;
    }

    spdlog::warn("retrieveData: Unknown location used {}", location);

    return *this;
}

ConnId& vnf::ConnId::delData(string tableName, int key, enum DataLocation location) {
    if (location == REMOTE) {
        /* TODO: fix this shit */
        if (globals.keyExistsInCachedRemoteDatastore(key)) {
            globals.dataStoreLock.lock();
            cache_void_list.erase(globals.cachedRemoteDatastore[key]);
            globals.dsMemPoolManager.free(globals.cachedRemoteDatastore[key]);
            globals.cachedRemoteDatastore.erase(key);
            globals.localDatastore.erase(key);
            globals.dataStoreLock.unlock();
        }
        // todo : complete this
        return *this;
    }

    if (location == LOCAL) {
        globals.dataStoreLock.lock();

        globals.dsMemPoolManager.free(globals.localDatastore[key]);
        globals.localDatastore.erase(key);

        globals.dataStoreLock.unlock();
        return *this;
    }

    spdlog::warn("delData: Unknown location used {}", location);

    return *this;
}

void vnf::ConnId::closeConn() {
    int socketId = this->socketId;
    int coreId = this->coreId;
    while (!perCoreStates[coreId].isPendingDataQueueEmpty(socketId)) {
        PendingData dataToSend = perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].front();
        int ret;
        if(globals.serverProtocol == "sctp"){
            ret = sctp_sendmsg(socketId, (void *) dataToSend.data, (size_t)dataToSend.dataLen, NULL, 0, 0, 0, dataToSend.streamNum, 0, 0);
        } else {
            ret = write(socketId, dataToSend.data, dataToSend.dataLen);
        }
        perCoreStates[coreId].packetsMemPoolManager.free((void *) dataToSend.data);
        perCoreStates[coreId].socketIdPendingDataQueueMap[socketId].pop();
        if (ret < 0) {
            spdlog::error("Connection closed with client");
            close(socketId);
            break;
        }
    }
    perCoreStates[coreId].delLeftOverPacketFragment(socketId);
    // todo free callback registrations
    perCoreStates[coreId].socketProtocolMap.erase(socketId);
    close(socketId);
}

void * vnf::allocReqObj(ConnId& connId, int reqObjType, int reqObjId) {
  return connId.allocReqObj(reqObjType, reqObjId);
}

ConnId& vnf::freeReqObj(ConnId connId, int reqObjType, int reqObjId) {
  return connId.freeReqObj(reqObjType, reqObjId);
}

ConnId& vnf::linkReqObj(ConnId connId, void *requestObj, int reqObjId) {
  return connId.linkReqObj(requestObj, reqObjId);
}

void * vnf::setPktDNE(ConnId& connId, void *packet) {
  return connId.setPktDNE(packet);
}

ConnId& vnf::unsetPktDNE(ConnId connId, void *packet) {
  return connId.unsetPktDNE(packet);
}

char * vnf::getPktBuf(ConnId& connId) {
  return connId.getPktBuf();
}

ConnId& vnf::registerCallback(ConnId& connId, enum EventType event, void callback(ConnId& connId, int reqObjId, void * requestObject, char * packet, int packetLen, int errorCode, int streamNum)) {
  return connId.registerCallback(event, callback);
}

ConnId& vnf::registerReqObjIdExtractor(ConnId& connId, int roidExtractor(char *packet, int packetLen)) {
  return connId.registerReqObjIdExtractor(roidExtractor);
}

ConnId& vnf::registerPacketBoundaryDisambiguator(ConnId& connId, vector<int> pbd(char *buffer, int bufLen)) {
  return connId.registerPacketBoundaryDisambiguator(pbd);
}

ConnId vnf::createClient(ConnId& connId, string localIP, string remoteIP, int remotePort, string protocol) {
  return connId.createClient(localIP, remoteIP, remotePort, protocol);
}

ConnId& vnf::sendData(ConnId& connId, char *packetToSend, int packetSize, int streamNum) {
  return connId.sendData(packetToSend, packetSize, streamNum);
}

ConnId& vnf::storeData(ConnId& connId, string tableName, int key, enum DataLocation location, void *value, int valueLen, void errorCallback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode)) {
  return connId.storeData(tableName, key, location, value, valueLen, errorCallback);
}

ConnId& vnf::retrieveData(ConnId& connId, string tableName, int key, enum DataLocation location, void callback(ConnId& connId, int reqObjId, void * requestObject, void * value, int valueLen, int errorCode), int reqObjId) {
  return connId.retrieveData(tableName, key, location, callback, reqObjId);
}

ConnId& vnf::delData(ConnId& connId, string tableName, int key, enum DataLocation location) {
  return connId.delData(tableName, key, location);
}

void vnf::closeConn(ConnId& connId) {
  return connId.closeConn();
}

