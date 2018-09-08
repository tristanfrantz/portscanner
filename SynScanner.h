// synscan.h
#ifndef SYNSCANNER_H
#define SYNSCANNER_H

#include <unistd.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <list>
#include <string>

#include <arpa/inet.h>

#include "utils.h"

using namespace std;

class SynScanner 
{
private:
    bool syn_ack_response(char* recv_packet, long dest_addr);
    void packet_sniffer(int recv_sock, long dest_addr, string host);
    void syn_scan(string host, vector<int> ports);

    mutex thread_mutex;
    map<string, list<int>> report;
    vector<thread> threads;
public:
    map<string, list<int>> syn_scan_range(vector<string> hosts, vector<int> ports);
};

#endif