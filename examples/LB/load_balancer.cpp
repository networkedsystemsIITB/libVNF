#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <sys/mman.h>
//#include <net/ethernet.h>
//#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <libvnf/core.hpp>
#define BACKEND_SERVERS 1

int backend_count = 1;
int lb_fd;
int index1 = 0;
struct my_pool
{
    int pktlen;
    char *dst1;
};

void process_receive_buffer(int fd1, void *request, char *buffer, int len, int err_code);

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2)
    {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len)
    {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static uint16_t
wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

/*
 * Rewrites destination mac address and ip address and send the packet
 */

uint16_t tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf = buff;
    uint16_t *ip_src = (void *)&src_addr, *ip_dst = (void *)&dest_addr;
    uint32_t sum;
    size_t length = len;

    // Calculate the sum                                            //
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if (len & 1)
        // Add the padding if the packet lenght is odd          //
        sum += *((uint8_t *)buf);

    // Add the pseudo-header                                        //
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries                                              //
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    // Return the one's complement of sum                           //
    return ((uint16_t)(~sum));
}
/*
 * Rewrites destination mac address and ip address and send the packet
 */
void send_tcp_packet1(int fd1, void *request, char *buffer, int len, int err_code)
{
    char *dst;
    my_pool *buffer_request = static_cast<my_pool *>(request);
    dst = buffer_request->dst1;
    struct ether_header *ethh = (struct ether_header *)dst;
    struct ip *ipd = (struct ip *)(ethh + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ipd + 1);
    inet_pton(AF_INET, buffer, &(ipd->ip_dst));
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    int i;
    //memcpy((void*)pkt,(void*)(packet),3);
    string bck_ip = buffer;
    int map_id = createClient(lb_fd, "169.254.127.246", bck_ip, 0, "tcp");
    /*rewrite destination mac  */
    /*probably packet is ready to send*/
    ipd->ip_sum = 0x0000;
    ipd->ip_sum = wrapsum(checksum(ipd, sizeof(*ipd), 0));
    //tcp checksum
    tcp->th_sum = 0;
    tcp->th_sum = tcp_checksum(tcp, (ntohs(ipd->ip_len) - 4 * ipd->ip_hl), ipd->ip_src.s_addr, ipd->ip_dst.s_addr);
    sendData(map_id, dst, buffer_request->pktlen);
    freeReqObj(lb_fd, 1);
    registerCallback(lb_fd, READ, process_receive_buffer);
}

void send_tcp_packet(const unsigned char *buffer, struct ip *iph, void *request, int length)
{

    char *dst = getPktBuf(0);
    struct ether_addr *p;
    my_pool *buffer_request = static_cast<my_pool *>(request);
    nm_pkt_copy(buffer, dst, length);
    //setSlotLen(length);
    buffer_request->dst1 = dst;
    struct ether_header *ethh = (struct ether_header *)dst;
    struct ip *ipd = (struct ip *)(ethh + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ipd + 1);
    buffer_request->pktlen = length;
    /* select backend from sport */
    char *backend_ip;
    index1 = htons(tcp->source) % backend_count;
    getData(lb_fd, "backend_IP", index1, LOCAL, send_tcp_packet1);
}

void process_ip_packet(const unsigned char *buffer, struct ip *iph, void *request, int length)
{
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    uint32_t source_ip;
    char *arp_buffer;
    struct ether_addr dest_mac;
    int i;
    struct arp_cache_entry *entry;
    switch (iph->ip_p)
    {
    case IPPROTO_TCP:
        send_tcp_packet(buffer, iph, request, length);
        break;
    case IPPROTO_IPIP:
        break;
    default:
        break;
    }
}
void update_from_controller(string task, string vnf_name, string vnf_ip, string event)
{
    char *to_send = vnf_ip.c_str();
    char *to_send1 = "169.254.9.101";
    if (task == "ADD")
    {
        if (backend_count == 1)
        {
            setData(lb_fd, "backend_IP", 1, LOCAL, (void *)to_send, vnf_ip.length(), NULL);
            backend_count++;
            setData(lb_fd, "backend_IP", 2, LOCAL, (void *)to_send, vnf_ip.length(), NULL);
            backend_count++;
            setData(lb_fd, "backend_IP", 3, LOCAL, (void *)to_send1, 13, NULL);
            backend_count++;
        }
    }
    else if (task == "DEL")
    {
        delData(lb_fd, "backend_IP", 1, LOCAL);
        backend_count--;
        delData(lb_fd, "backend_IP", 2, LOCAL);
        backend_count--;
        delData(lb_fd, "backend_IP", 3, LOCAL);
        backend_count--;
        cout << "deleted" << endl;
    }
}
void process_receive_buffer(int fd1, void *request, char *buffer, int len, int err_code)
{
    struct ether_header *ethh = (struct ether_header *)buffer;
    request = allocReqObj(fd1, 1);
    my_pool *buf_req = static_cast<my_pool *>(request);
    switch (ntohs(ethh->ether_type))
    {
    case ETHERTYPE_IP:
        process_ip_packet(buffer, (struct ip *)(ethh + 1), request, len);
        break;
    case ETHERTYPE_IPV6:
        // printf("packet received: IPV6 packet\n");
        break;
    case ETHERTYPE_VLAN:
        // printf("vlan\n");
        break;
    case ETHERTYPE_ARP:
        /*ARP packet */
        // printf("##################################################################################\n");
        // printf("Packet received: ARP packet\n");

        handle_arp_packet(buffer);
        // printf("##################################################################################\n");
        break;
    default:
        /* others */
        break;
    }
}

int main()
{
    char *buf;
    char *src, *dst;
    uint16_t *spkt, *dpkt;
    struct ether_addr *p;
    uint32_t source_ip;

    vector<int> dataStorePorts;
    dataStorePorts.push_back(7000);
    dataStorePorts.push_back(7001);
    dataStorePorts.push_back(7002);
    dataStorePorts.push_back(7003);
    initLibvnf(1, 128, "127.0.0.1", dataStorePorts, 131072, false);

    lb_fd = createServer("eth5", "169.254.127.246", NULL, "tcp");
    registerCallback(lb_fd, READ, process_receive_buffer);
    registerforNotification("169.254.9.74", update_from_controller);
    int reqpool[1] = {64};
    initReqPool(reqpool, 1);
    char *to_send = "169.254.9.101";
    setData(lb_fd, "backend_IP", 0, LOCAL, (void *)to_send, 14, NULL);
    /*   setData(lb_fd, "backend_IP", 0, 1, LOCAL, "169.254.9.38");
        backend_count++;
  setData(lb_fd, "backend_IP", 0, 2, LOCAL, "169.254.9.28");
        backend_count++;
  setData(lb_fd, "backend_IP", 0, 3, LOCAL, "169.254.9.28");
      backend_count++;
  setData(lb_fd, "backend_IP", 0, 4, LOCAL, "169.254.9.8");
      backend_count++;
  setData(lb_fd, "backend_IP", 0, 5, LOCAL, "169.254.9.8");
      backend_count++;
        setData(lb_fd, "backend_IP", 0, 6, LOCAL, "169.254.9.38");
        backend_count++;
        setData(lb_fd, "backend_IP", 0, 1, LOCAL, "169.254.9.33");
  backend_count++;*/
    //for 4 replica case uncomment
    startEventLoop();
}
