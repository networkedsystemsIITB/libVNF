#ifndef RAN_SIMULATOR_H
#define RAN_SIMULATOR_H

#include "network.h"
#include "packet.h"
#include "ran.h"
#include "sctp_client.h"
#include "sync.h"
#include "telecom.h"
#include "utils.h"
#include "common.h"

#define NUM_MONITORS 50

extern time_t g_start_time;
extern int g_threads_count;
extern uint64_t g_req_duration;
extern uint64_t g_run_duration;
extern int g_tot_regs;
extern uint64_t g_tot_regstime;
extern pthread_mutex_t g_mux;

extern vector<thread> g_threads;
extern thread g_rtt_thread;

void simulate(int);
void check_usage(int);
void init(char**);
void run();
void print_results();
int createServerSocket(int portNo);

#endif /* RAN_SIMULATOR_H */
