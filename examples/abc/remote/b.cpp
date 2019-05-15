#include <libvnf/core.hpp>

struct mme_state {
    char *req;
    void *dsreq;
    int val1;
    int vnf_id;
    char b[5];

};

string mme_ip;
string neighbour1_ip;
int mme_port;
int neighbour1_port;

char *temp_data = "hello";

void handle_ds_reply1(int conn_id, void *request, void *packet, int packet_len, int err_code) {
    int a = 5, i, key_id, id, vconn_id;
    string connid = to_string(conn_id);
    mme_state *x = static_cast<mme_state *>(request);
    id = conn_id / 10000000;
    vconn_id = conn_id % (10000000);
    if (id == 1) {
        key_id = 100000 + vconn_id;

    } else if (id == 2) {
        key_id = 200000 + vconn_id;
    } else if (id == 3) {
        key_id = 300000 + vconn_id;
    } else if (id == 4) {
        key_id = 400000 + vconn_id;
    } else if (id == 5) {
        key_id = 500000 + vconn_id;
    } else if (id == 6) {
        key_id = 600000 + vconn_id;
    } else if (id == 7) {
        key_id = 700000 + vconn_id;
    } else {
        key_id = 800000 + vconn_id;
    }

    x->dsreq = setKeyDNE(key_id);
    unsetKeyDNE(key_id);
    unsetPktDNE(conn_id, (void *) x->req);
    char *pkt = getPktBuf(conn_id);
    memcpy((void *) pkt, (void *) (packet), 3);
    sendData(conn_id, pkt, 3);
    freeReqObj(conn_id, 1);

    delData(conn_id, "", key_id, LOCAL);
}

void handle_c_reply1(int conn_id, void *request, char *packet, int packet_len, int err_code) {
    int a = 5, i, key_id, id;
    mme_state *x = static_cast<mme_state *>(request);
    int server_id = x->vnf_id;
    freeReqObj(conn_id, 1);
    id = conn_id / 10000000;
    if (id == 1) {
        key_id = 100000 + server_id;
    } else if (id == 2) {
        key_id = 200000 + server_id;
    } else if (id == 3) {
        key_id = 300000 + server_id;
    } else if (id == 4) {
        key_id = 400000 + server_id;
    } else if (id == 5) {
        key_id = 500000 + server_id;
    } else if (id == 6) {
        key_id = 600000 + server_id;
    } else if (id == 7) {
        key_id = 700000 + server_id;
    } else {
        key_id = 800000 + server_id;
    }
    int s_id = id * 10000000 + server_id;

    getData(s_id, "", key_id, LOCAL, handle_ds_reply1);

}

void handle_ue(int conn_id, void *request, char *packet, int packet_len, int err_code) {
    int a = conn_id, i, key_id, c_id, id, vconn_id;
    id = conn_id / 10000000;
    vconn_id = conn_id % (10000000);
    request = allocReqObj(conn_id, 1);
    c_id = createClient(conn_id, mme_ip, neighbour1_ip, neighbour1_port, "tcp");
    for (i = 1; i < 20000000; i++) {
        a = a + i;
    }
    mme_state *x = static_cast<mme_state *>(request);
    x->val1 = a;
    x->b[0] = 'a';
    x->b[1] = 'b';
    x->b[2] = '\0';
    x->req = (char *) getPktDNE(conn_id, (void *) packet);
    linkReqObj(c_id, request);
    registerCallback(c_id, READ, handle_c_reply1);
    x->vnf_id = vconn_id;
    if (id == 1) {
        key_id = 100000 + vconn_id;

    } else if (id == 2) {
        key_id = 200000 + vconn_id;

    } else if (id == 3) {
        key_id = 300000 + vconn_id;
    } else if (id == 4) {
        key_id = 400000 + vconn_id;
    } else if (id == 5) {
        key_id = 500000 + vconn_id;
    } else if (id == 6) {
        key_id = 600000 + vconn_id;
    } else if (id == 7) {
        key_id = 700000 + vconn_id;
    } else {
        key_id = 800000 + vconn_id;
    }
    char *to_send = "pq";

    setData(conn_id, "", key_id, LOCAL, (void *) to_send, 3, NULL);

    char *pkt = getPktBuf(conn_id);
    memcpy((void *) pkt, (void *) (x->b), 3);
    sendData(c_id, pkt, 3);
}

int main(int argc, char *argv[]) {
    vector<int> dataStorePorts;
    dataStorePorts.push_back(7000);
    dataStorePorts.push_back(7001);
    dataStorePorts.push_back(7002);
    dataStorePorts.push_back(7003);
    initLibvnf(8, 128, "169.254.9.18", dataStorePorts, 131072, false);

    mme_ip = "169.254.9.102";
    mme_port = 5000;
    neighbour1_ip = "169.254.9.78";
    neighbour1_port = 6000;

    int serverID = createServer("", mme_ip, mme_port, "tcp");
    registerCallback(serverID, READ, handle_ue);
    int reqpool[1] = {sizeof(struct mme_state)};
    initReqPool(reqpool, 1);
    startEventLoop();
    return 0;
}
