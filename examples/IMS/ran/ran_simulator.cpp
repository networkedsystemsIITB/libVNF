#include "ran_simulator.h"

time_t g_start_time;
int g_threads_count;
uint64_t g_req_dur;
uint64_t g_run_dur;
int g_tot_regs;
uint64_t g_tot_regstime;
pthread_mutex_t g_mux;

vector<thread> g_umon_thread;
vector<thread> g_threads;

uint32_t ueClientPort;	
uint32_t ueServerSocket;
int listenSocket;

//Functions to call register, authenticate,deregister
void register1(int ran_num)
{
	Ran ran;
	ran.init(ran_num);
	ran.conn_pcscf();
	ran.register1();	
}
void authenticate(int ran_num)
{
	Ran ran;
	ran.init(ran_num);
	ran.conn_pcscf();
	ran.authenticate();
}
void deregsiter(int ran_num)
{
	Ran ran;
	ran.init(ran_num);
	ran.conn_pcscf();
	ran.deregsiter();
}

void simulate(int arg) {
	CLOCK::time_point mstart_time;
	CLOCK::time_point mstop_time;
	MICROSECONDS mtime_diff_us;		
	
	int status;
	int ran_num;
	bool ok;
	bool time_exceeded;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	ran_num = arg;
	time_exceeded = false;

	while (1) {

		g_utils.time_check(g_start_time, g_req_dur, time_exceeded);
		if (time_exceeded) {
			break;
		}		

		mstart_time = CLOCK::now();	
		register1(ran_num);
		authenticate(ran_num);
		deregsiter(ran_num);
			/*ok = ran.authenticate();
		if (!ok) {
			TRACE(cout << "ransimulator_simulate:" << " autn failure" << endl;)
			return;
		} 

		Ran ran1;
		ran1.init(ran_num);
		ran1.ran_ctx.pcscf_socket=ran1.conn_pcscf();

		
		ok = ran1.deregsiter();
		if (!ok) {
			TRACE(cout << "ransimulator_simulate:" << " detach failure" << endl;)
			return;
		} */
		
		mstop_time = CLOCK::now();
		
		// Response time
		mtime_diff_us = std::chrono::duration_cast<MICROSECONDS>(mstop_time - mstart_time);


		g_sync.mlock(g_mux);
		g_tot_regs++;
		g_tot_regstime += mtime_diff_us.count();		
		g_sync.munlock(g_mux);		
		
	}
}

void check_usage(int argc) {
	if (argc < 3) {
		TRACE(cout << "Usage: ./<ran_simulator_exec> THREADS_COUNT DURATION" << endl;)
		g_utils.handle_type1_error(-1, "Invalid usage error: ransimulator_checkusage");
	}
}

void init(char *argv[]) {
	g_start_time = time(0);
	g_threads_count = atoi(argv[1]);
	g_req_dur = atoi(argv[2]);
	g_tot_regs = 0;
	g_tot_regstime = 0;
	g_sync.mux_init(g_mux);	
	g_threads.resize(g_threads_count);
	signal(SIGPIPE, SIG_IGN);
}

void run() {
	int i;
	for (i = 0; i < g_threads_count; i++) {
		g_threads[i] = thread(simulate, i);
	}	

	for (i = 0; i < g_threads_count; i++) {
		if (g_threads[i].joinable()) {
			g_threads[i].join();
		}
	}	
}


void print_results() {
	g_run_dur = difftime(time(0), g_start_time);
	
	cout << endl << endl;
	cout << "Requested duration has ended. Finishing the program." << endl;
	cout << "Total number of registrations is " << g_tot_regs << endl;
	cout << "Total time for registrations is " << g_tot_regstime * 1e-6 << " seconds" << endl;
	cout << "Total run duration is " << g_run_dur << " seconds" << endl;
	cout << "Latency is " << ((double)g_tot_regstime/g_tot_regs) * 1e-6 << " seconds" << endl;
	cout << "Throughput is " << ((double)g_tot_regs/g_run_dur) << endl;	
}

int main(int argc, char *argv[]) {
	check_usage(argc);
	init(argv);
	run();
	print_results();
	return 0;
}
