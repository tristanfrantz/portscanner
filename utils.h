/* utils.h
 * Common utilities used by the port scanners
 */

#ifndef UTILS_H
#define UTILS_H

#include <random>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>

const int MAX_PORT = 65535; 
const int DYNAMIC_PORT = 49152;
const int INTERVAL = 500;

/* "Pseudo tcp header" used for checksum calculation */
struct tcp_pheader {
    unsigned int source_address; // 4 byte/s
    unsigned int dest_address;   // 4 byte/s
    unsigned char reserved;      // 1 byte/s
    unsigned char protocol;      // 1 byte/s
    unsigned short tcp_length;   // 2 byte/s
    struct tcphdr tcph;
};

struct sockaddr_in get_sockaddr_in(const char* hostname, int port);
unsigned short checksum(unsigned short *addr, int len);
int random_number(int min, int max);
void create_iph(struct ip *iph, long source_addr, long dest_addr);
void create_tcph(struct tcphdr *tcph, short port, short flags);
void set_tcph_checksum(struct tcphdr *tcph, long source_addr, long dest_addr);
void set_tcph_port(struct tcphdr *tcph, short port);
void get_local_ip(char* buffer);

#endif