#ifndef B_H
#define B_H
extern string mme_ip;
extern int mme_port;

void handle_ue(int conn_id, void *request, char *packet, int packet_len, int err_code);

void handle_c_reply1(int conn_id, void *request, char *packet, int packet_len, int err_code);

void handle_ds_reply1(int conn_id, void *request, char *packet, int packet_len, int err_code);

#endif
