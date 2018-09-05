#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <vector>
#include <random>
#include <thread>
#include <mutex>
#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <iostream>

#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>

#include <err.h>
#include <sysexits.h>

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

/* checksum calculation function inpired by src:
   http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c */
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

struct sockaddr_in get_sockaddr_in(const char* hostname, int port){
    struct hostent *server;
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
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

/* Check if port is open via connect to host:port */
bool port_open(struct sockaddr_in serv_addr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Open TCP socket
    if (sockfd < 0)
        cout << "ERROR opening socket" << endl;

    int conn = connect(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr));
    close(sockfd);

    // port open if connect works
    if (conn == 0)
        return true;

    // port closed if connect fails
    return false;
}

/* Open tcp connect 3-way handshake thingy */
void tcp_scan(string host, vector<int> ports) {
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        if (port_open(addr)) {
            //m.lock();
            printf("Port %d is open\n", port);
            //m.unlock();
        }
        // int rand_interval = random_number(0, 500);
        // this_thread::sleep_for (chrono::milliseconds(500 + rand_interval));
    }
}


void packet_syn(char* buffer, int size, long dest)
{
    struct ip *iph = (struct ip*)buffer;
    long src = iph->ip_src.s_addr;

    if(iph->ip_p == IPPROTO_TCP && src == dest)
    {
        struct tcphdr *tcph=(struct tcphdr*)(buffer + iph->ip_hl * 4);

        if(tcph->th_flags == (TH_SYN|TH_ACK))
        {
            printf("Port %d open \n" , ntohs(tcph->th_sport));
            fflush(stdout);
        }
    }
}

/* TCP SYN SCAN */
void syn_scan(string host, vector<int> ports) {
  /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able to
     send any IP protocol that is specified in the passed header.*/
  int raw_socket = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
  long source_addr = inet_addr("10.0.1.64");

  char packet[4096] = {0};
  struct ip *iph = (struct ip *) packet;
  struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

  /* create the ip header */
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);    /* no payload */
  iph->ip_id = 0;    /* the value doesn't matter here */
  iph->ip_off = 0;
  iph->ip_ttl = 255;
  iph->ip_p = IPPROTO_TCP;
  iph->ip_sum = 0;        /* set it to 0 before computing the actual checksum later */
  iph->ip_src.s_addr = source_addr;/* SYN's can be blindly spoofed */
  iph->ip_dst.s_addr = sin.sin_addr.s_addr;
  iph->ip_sum = checksum ((unsigned short *) packet, iph->ip_len);

  /* create the tcp header */
  tcph->th_sport = htons(57290);    /* source port shouldn't matter; can use any */
  tcph->th_dport = htons(31337);
  tcph->th_seq = static_cast<unsigned int>(random());/* in a SYN packet, the sequence is a random */
  tcph->th_ack = 0; /* number, and the ack sequence is 0 in the 1st packet */
  tcph->th_off = sizeof(struct tcphdr) / 4;        /* first and only tcp segment */
  tcph->th_flags = TH_SYN;    /* initial connection request */
  tcph->th_win = htons(65535);    /* maximum allowed window size */
  tcph->th_sum = 0; /* if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission */
  tcph->th_urp = 0;

  /* scan random-ordered ports */
  for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
    tcph->th_dport = htons(*it);
    tcph->th_sum = 0;

    struct tcp_pheader tcp_ph;
    tcp_ph.source_address = source_addr;
    tcp_ph.dest_address = sin.sin_addr.s_addr;
    tcp_ph.reserved = 0;
    tcp_ph.protocol = IPPROTO_TCP;
    tcp_ph.tcp_length = htons( sizeof(struct tcphdr) );

    memcpy(&tcp_ph.tcph, tcph, sizeof (struct tcphdr));

    tcph->th_sum = checksum( (unsigned short*) &tcp_ph , sizeof (struct tcp_pheader));

    // Sending packet
    if (sendto (raw_socket, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        cout << "error sending packet" << endl;

    // Receiving response packet
    int read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    char read_buffer[60*1024] = {0};
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof saddr;
    int msg_len = recvfrom(read_sock ,read_buffer, sizeof(read_buffer), 0, &saddr, &saddr_size);

    if(msg_len < 0)
        cout << "recvfrom: failed to get packets" << endl;

    long dest_addr = sin.sin_addr.s_addr;
    packet_syn(read_buffer, msg_len, dest_addr);
  }
}

void ack_scan(string host, std::vector<int> ports) {

}

void syn_ack_scan(string host, vector<int> ports) {

}

void fin_scan(string host, vector<int> ports) {

}

int main (void) {
    vector<string> hosts = {"scanme.nmap.org"};
    vector<int> ports = {49176, 631, 5232, 21, 31337, 49157, 7070, 554};
    //tcp_scan(hosts[0], ports);
    syn_scan(hosts[0], ports);
    //syn_ack_scan(hosts[0], ports);

    return 0;
}
