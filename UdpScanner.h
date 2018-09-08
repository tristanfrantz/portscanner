#ifndef UDPSCANNER_H
#define UDPSCANNER_H

#include <iostream>
#include <netinet/ip_icmp.h>
#include <thread>
#include <mutex>
#include <map>
#include <list>

#include "utils.h"
using namespace std;

class UdpScanner 
{
private:
    bool icmp_response(int fd);
    void send_udp_packet(int send_sock, sockaddr_in addr);
    void udp_scan(string host, vector<int> ports);

    mutex thread_mutex;
    map<string, list<int>> report;
    vector<thread> threads;
public:
    map<string, list<int>> udp_scan_range(vector<string> hosts, vector<int> ports);
};

#endif