//tcpscan.h
#ifndef TCPSCANNER_H
#define TCPSCANNER_H

#include <unistd.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <list>

#include "utils.h"

using namespace std;


class TcpScanner 
{
private:
    bool connect_to_host(struct sockaddr_in serv_addr);
    void tcp_scan(string host, vector<int> ports);

    mutex thread_mutex;
    map<string, list<int>> report;
    vector<thread> threads;
public:
    map<string, list<int>> tcp_scan_range(vector<string> hosts, vector<int> ports);
};


#endif