// utils.cpp
#include "utils.h"

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

/* calculates and sets the checksum of a tcp header */
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

// src: https://tinyurl.com/ya5prw53
void get_local_ip ( char * buffer) {
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
 
    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;
 
    struct sockaddr_in serv;
 
    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );
 
    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
 
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
 
    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
 
    close(sock);
}