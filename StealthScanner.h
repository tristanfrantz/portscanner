#ifndef STEALTHSCANNER_H
#define STEALTHSCANNER_H

#include <set>
#include <vector>
#include <map>
#include <list>
#include <thread>
#include <mutex>
#include <iostream>


#include <arpa/inet.h>

#include "utils.h"

using namespace std;

class StealthScanner 
{
private:
    void stealth_scan(string host, vector<int> ports, short flags);

    mutex thread_mutex;
    map<string, list<int>> report;
    vector<thread> threads;
public:
    map<string, list<int>> stealth_scan_range(vector<string> hosts, vector<int> ports, short flags);
};

#endif