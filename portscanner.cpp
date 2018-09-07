#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <vector>
#include <set>
#include <random>
#include <thread>
#include <mutex>
#include <chrono>
#include <thread>
#include <iostream>
#include <algorithm>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>


const int MAX_PORT = 65535; 
const int DYNAMIC_PORT = 49152;
const int INTERVAL = 500;

using namespace std;

/* "Pseudo header" needed for checksum calculation */
struct tcp_pheader
{
    unsigned int source_address; // 4 byte/s
    unsigned int dest_address;   // 4 byte/s
    unsigned char reserved;      // 1 byte/s
    unsigned char protocol;      // 1 byte/s
    unsigned short tcp_length;   // 2 byte/s
    struct tcphdr tcph;
};

/* checksum calculation function; src:
   http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c 
*/
unsigned short checksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

int random_number(int min, int max){
	std::random_device seeder;

	std::mt19937 rng(seeder());
	std::uniform_int_distribution<int> gen(min, max);
	int r = gen(rng);
	return r;
}

struct sockaddr_in get_sockaddr_in(const char* hostname, int port){
    struct hostent *server;
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"Error: could not resolve host/s.\n");
        exit(0);
    }
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr,
           (char *)server->h_addr,
           server->h_length);
    serv_addr.sin_port = htons(port);

    return serv_addr;
}

/* Check if connection is successful via connect to host:port
 * return true if connection was a success
 * else return false
 */
bool connect_to_host(struct sockaddr_in serv_addr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Open TCP socket
    if (sockfd < 0)
        cerr << "ERROR opening socket" << endl;

    int conn = connect(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr));
    close(sockfd);
    // connection successful
    if (conn == 0)
        return true;
    // connection unsuccessful  
    return false;
}

/* Open tcp scan(3-way handshake) */
void tcp_scan(string host, vector<int> ports) {
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        bool port_is_open = connect_to_host(addr);
        if (port_is_open) {
            cout << "Port " << port <<  " is open" << endl;
        }
        // int rand_interval = random_number(0, 500);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL));
    }
}

bool icmp_response(int fd) {
    char buf[1024] = {0};
    struct ip* iphd;
    struct icmp* icmph;

    timeval time_val;
    time_val.tv_sec = 2;
    time_val.tv_usec = 0;
    /* setting them options boy */
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) != 0)
        cerr << "Oh no spaghettio: could not set socket option" << endl; 

    ssize_t len = recvfrom(fd, &buf, sizeof(buf), 0, NULL, NULL);
    if(len > 0){
        struct ip* iphd = (struct ip*)(buf);
        struct icmp* icmph = (struct icmp*)(buf + iphd->ip_hl*4);

        //Not necessary 
        if((icmph->icmp_type == ICMP_UNREACH) && (icmph->icmp_type == ICMP_UNREACH_PORT))
            return true; // open port
    }
    return false; // closed port
}

void send_udp_packet(int send_sock, sockaddr_in addr) {
    const char* buf;
    if(sendto(send_sock, buf, 0, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        cerr << "sendto(): failed" << endl;
}

/* UDP scan (ICMP_PORT_UNREACHABLE)*/
void udp_scan(string host, vector<int> ports) {
    // Open UDP socket to send UDP packet
    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0)
        cerr << "Oh no spaghettio: could not open socket" << endl;
    
    // Open RAW socket to read received packet
    int read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (read_sock < 0)
        cerr << "Oh no spaghettio: could not open socket" << endl;
    
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        send_udp_packet(send_sock, addr);
        bool port_is_closed = icmp_response(read_sock);

        if(!port_is_closed)
            cout << "Port " << port <<  " is open" << endl;
        else
            cout << "Port " << port << " is closed" << endl;

        this_thread::sleep_for (chrono::milliseconds(INTERVAL));
    }
}

/* Check if received packet:
 * 1. Is using tcp protocol
 * 2. Is from the host address
 * 3. Has syn|ack flags set
 */
bool syn_ack_response(char* recv_packet, long dest_addr) {
    struct ip *iph = (struct ip*)recv_packet;
    char iph_protocol = iph->ip_p;
    long source_addr = iph->ip_src.s_addr;
    int iph_size = iph->ip_hl*4;
    

    if(iph_protocol == IPPROTO_TCP &&source_addr == dest_addr){
        struct tcphdr *tcph=(struct tcphdr*)(recv_packet + iph_size);
        if(tcph->th_flags == (TH_SYN|TH_ACK))
            return true;
    }
    return false;
}

/* One of the most sophisticated packet sniffers
 * out there today, the packet sniffer 3000
*/
void packet_sniffer_3000(int recv_sock, long dest_addr) {
    while(1)
    {
        char recv_packet[4096] = {0};
        if(recv(recv_sock ,recv_packet, sizeof(recv_packet), 0) < 0)
            cerr << "error: failed to recv packets" << endl;

        bool port_is_open = syn_ack_response(recv_packet, dest_addr);

        if (port_is_open){
            struct tcphdr *tcph=(struct tcphdr*)(recv_packet + sizeof(struct ip));

            short port = ntohs(tcph->th_sport);
            cout << "Port " << port << " is open" << " on:" << dest_addr << endl; 
        }
    }
    cout << "goes here ?" << endl;
}


/* create an ip header with the specified source and destination addresses */
void create_iph(struct ip *iph, long source_addr, long dest_addr) {
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof (struct tcphdr);
    iph->ip_id = 0;    
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = source_addr;
    iph->ip_dst.s_addr = dest_addr;
    iph->ip_sum = 0; // kernel calculates checksum
}

/* create a tcp header with the specified destination port and flags */
void create_tcph(struct tcphdr *tcph, short port, short flags) {
    int rand_port = random_number(DYNAMIC_PORT, MAX_PORT);
    tcph->th_sport = htons(rand_port); // has to be > than the dynamically assigned range
    tcph->th_dport = htons(port);
    tcph->th_seq = 0; 
    tcph->th_ack = 0;
    tcph->th_off = sizeof(struct tcphdr) / 4; // number of 32-bit words in tcp header(where tcph begins)
    tcph->th_flags = flags;    
    tcph->th_win = htons(65535);              // maximum allowed window size 
    tcph->th_sum = 0;
    tcph->th_urp = 0;
}

/* calculates and sets the checksum of the tcp header */
void set_tcph_checksum(struct tcphdr *tcph, long source_addr, long dest_addr) {
    tcph->th_sum = 0;
    struct tcp_pheader tcp_ph;
    tcp_ph.source_address = source_addr;
    tcp_ph.dest_address = dest_addr;
    tcp_ph.reserved = 0;
    tcp_ph.protocol = IPPROTO_TCP;
    tcp_ph.tcp_length = htons( sizeof(struct tcphdr) );
    memcpy(&tcp_ph.tcph, tcph, sizeof (struct tcphdr));
    tcph->th_sum = checksum( (unsigned short*) &tcp_ph , sizeof (struct tcp_pheader));
}

void set_tcph_port(struct tcphdr *tcph, short port) {
    tcph->th_dport = htons(port);
}

/* tcp syn scan host with the provided random ordered ports */
void syn_scan(string host, vector<int> ports) {
  /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able to
     send any IP protocol that is specified in the passed header.*/
  int send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (send_sock < 0)
        cerr << "ERROR opening socket" << endl;

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0)
        cerr << "ERROR opening socket" << endl;

    struct timeval time_val;
    time_val.tv_sec = 5;  /* 5 sec Timeout */
    if(setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&time_val,sizeof(struct timeval)) < 0)
        cerr << "Oh no spaghettio: could not set socket options" << endl;

  struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
  long source_addr = inet_addr("10.0.1.64");
  long dest_addr = sin.sin_addr.s_addr;
  short flags = TH_SYN;

  char packet[4096] = {0};
  struct ip *iph = (struct ip *) packet;
  struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

  /* create the ip header */
  create_iph(iph, source_addr, dest_addr);

  /* create the tcp header */
  create_tcph(tcph, ports[0], flags);

  /* start sniff sniffing for a syn ack response */
  thread sniff(packet_sniffer_3000, recv_sock, dest_addr);

  /* send syn packet to host on the random-ordered ports */
  for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
    short port = *it;
    set_tcph_port(tcph, port);
    set_tcph_checksum(tcph, source_addr, dest_addr);

    // Sending packet with syn flag   
    if (sendto (send_sock, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        cout << "error sending packet" << endl;

    this_thread::sleep_for (chrono::milliseconds(500));
  }
  sniff.detach();
  close(recv_sock);
}

/* stealth scan host with the provided random ordered ports
 * can be any of the following stealth scans:
 * SYN|ACK
 * XMAX (all flags)
 * NULL (no flags)
 * FIN
 * note: the stealth scan produces false positives
 */
void stealth_scan(string host, vector<int> ports, short flags){
  /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able to
     send any IP protocol that is specified in the passed header.*/
  int send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
  long source_addr = inet_addr("10.0.1.64");
  long dest_addr = sin.sin_addr.s_addr;
  
  char packet[4096] = {0};
  struct ip *iph = (struct ip *) packet;
  struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

  /* create the ip header */
  create_iph(iph, source_addr, dest_addr);

  /* create the tcp header */
  create_tcph(tcph, ports[0], flags);

  /* scan random-ordered ports */
  set<int> closed_ports;
  for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
    short port = htons(*it);
    set_tcph_checksum(tcph, source_addr, dest_addr);
    set_tcph_port(tcph, port);

    // Sending packet
    if (sendto (send_sock, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        cout << "error sending packet" << endl;
        return;
    }

    // Receiving response packet
    int read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct timeval tv;
    tv.tv_sec = 2;  /* 2 sec Timeout */
    setsockopt(read_sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

    char recv_packet[60*1024] = {0};
    recv(read_sock ,recv_packet, sizeof(recv_packet), 0);

    // Proccess recv packet
    struct ip *iph = (struct ip*)recv_packet;
    long source_addr = iph->ip_src.s_addr;

    if(iph->ip_p == IPPROTO_TCP && source_addr == dest_addr)
    {
        struct tcphdr *tcph=(struct tcphdr*)(recv_packet + iph->ip_hl * 4);

        if(tcph->th_flags == (TH_RST))
        {
            short port = ntohs(tcph->th_sport);
            closed_ports.insert(port);
        }
    }
  }
  /* iterate through all ports. If the port is not in the closed port set
   * it could be open or filtered
   */
  for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
      int port = *it;
      const bool is_in = closed_ports.find(port) != closed_ports.end();
      if(!is_in) {
          cout << "Port " << port << " open|filtered" << endl; 
      }
  }
}

/* stealth scan range of IPs with the provided random ordered ports
 * can be set to any of the following stealth scans:
 * SYN|ACK
 * XMAX (all flags)
 * NULL (no flags)
 * FIN
 * the only difference is which flags are set
 */
void stealth_scan_range(vector<string> hosts, vector<int> ports, short flags) {
    vector<thread> threads;

    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(stealth_scan, host, ports, flags));
    }

    for (vector<thread>::iterator it = threads.begin() ; it != threads.end() ; ++it)
    {
        it->join();
    }
}

void syn_scan_range(vector<string> hosts, vector<int> ports) {
    vector<thread> threads;

    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(syn_scan, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin() ; it != threads.end() ; ++it)
    {
        it->join();
    }
}

void tcp_scan_range(vector<string> hosts, vector<int> ports) {
    vector<thread> threads;

    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(tcp_scan, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin() ; it != threads.end() ; ++it)
    {
        it->join();
    }
}

void udp_scan_range(vector<string> hosts, vector<int> ports) {
    vector<thread> threads;

    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(udp_scan, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin() ; it != threads.end() ; ++it)
    {
        it->join();
    }
}


int main (int argc, char** argv) {
    vector<string> hosts = {"skel.ru.is", "scanme.nmap.org"};
    vector<int> ports = {49176, 631, 5232, 21, 22, 80, 8080, 31337, 49157, 7070, 554, 1231, 2342, 5232, 5245, 6254, 2323, 123, 68};

    /* randomize the vectors (ports and hosts) */
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    default_random_engine engine(seed);
    shuffle(ports.begin(), ports.end(), engine);
    shuffle(hosts.begin(), hosts.end(), engine);

    // start scanning!
    int opt;
    short flags = 0;
    string scan_type = "";
    switch (opt = getopt(argc, argv, "tsfxnau")) {
        case 't':
            tcp_scan_range(hosts, ports);
            break;
        case 's':
            syn_scan_range(hosts, ports);
            break;
        case 'u':
            udp_scan_range(hosts, ports);
            break;
        case 'f':
            flags = (TH_FIN);
            stealth_scan_range(hosts, ports, flags);
            break;
        case 'x':
            flags = (TH_ACK|TH_FIN|TH_PUSH|TH_RST|TH_SYN|TH_URG);
            stealth_scan_range(hosts, ports, flags);
            break;
        case 'n':
            flags = 0;
            stealth_scan_range(hosts, ports, flags);
            break;
        case 'a':
            flags = (TH_SYN|TH_ACK);
            stealth_scan_range(hosts, ports, flags);
            break;
        case '?':
            cerr << "Unknown option: '" << char(optopt) << "'!" << endl;
            break;
        default:
            syn_scan_range(hosts, ports);
            break;
    }


    return 0;
}
