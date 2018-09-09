#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fstream>

#include <vector>
#include <algorithm>
#include <map>
#include <list>
#include <string>

#include "TcpScanner.h"
#include "SynScanner.h"
#include "UdpScanner.h"
#include "StealthScanner.h"

const string HOSTS_FILE_NAME = "hosts.txt";
const string PORTS_FILE_NAME = "ports.txt";

/* Get ports via text file */
vector<int> get_ports();
/* Get hosts via text file */
vector<string> get_hosts();
/* Prints out report; which ports are open and how many are closed */
void print_report(map<string, list<int>> report, int port_count);


int main (int argc, char** argv) {
    vector<string> hosts = get_hosts();
    vector<int> ports = get_ports();
    map<string, list<int>> report;

    /* Randomize the vectors (ports and hosts) */
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    default_random_engine engine(seed);
    shuffle(ports.begin(), ports.end(), engine);
    shuffle(hosts.begin(), hosts.end(), engine);

    /* Lets start scanning! */
    int opt;
    short flags = 0;
    SynScanner synscanner;
    TcpScanner tcpscanner;
    UdpScanner udpscanner;
    StealthScanner stealthscanner;
    switch (opt = getopt(argc, argv, "tsfxnyu")) {
        case 't':
            cout << "Starting TCP scan..." << endl;
            report = tcpscanner.tcp_scan_range(hosts, ports);
            break;
        case 's':
            cout << "Starting SYN scan..." << endl;
            report = synscanner.syn_scan_range(hosts, ports);
            break;
        case 'u':
            cout << "Starting UDP scan..." << endl;
            report = udpscanner.udp_scan_range(hosts, ports);
            break;
        case 'f':
            flags = (TH_FIN);            
            cout << "Starting FIN scan..." << endl;
            report = stealthscanner.stealth_scan_range(hosts, ports, flags);
            break;
        case 'x':
            flags = (TH_ACK|TH_FIN|TH_PUSH|TH_RST|TH_SYN|TH_URG);        
            cout << "Starting XMAS scan..." << endl;
            report = stealthscanner.stealth_scan_range(hosts, ports, flags);
            break;
        case 'n':
            flags = 0;
            cout << "Starting NULL scan..." << endl;
            report = stealthscanner.stealth_scan_range(hosts, ports, flags);
            break;
        case 'y':
            flags = (TH_SYN|TH_ACK);
            cout << "Starting SYN ACK scan..." << endl;
            report = stealthscanner.stealth_scan_range(hosts, ports, flags);
            break;
        default:
            cout << "Starting SYN scan..." << endl;
            report = synscanner.syn_scan_range(hosts, ports);
            break;
    }

    print_report(report, ports.size());

    return 0;
}

void print_report(map<string, list<int>> report, int port_count) {
    if (report.empty()) {
        cout << "No open ports found" << endl;
    }

    for( const auto& pair : report ) {
        string host = pair.first;
        list<int> open_ports = pair.second;
        
        cout << "Scan report for " << host << endl;
        cout << "Closed ports(not shown): " << port_count - open_ports.size() << endl;
        for( int port : open_ports ) {
            cout << port << " is open" << endl;
        }
        cout << endl;
    }
}

vector<int> get_ports() {
    vector<int> ports;
    string line;
    ifstream portsfile (PORTS_FILE_NAME);
    if (portsfile.is_open())
    {
        while ( getline (portsfile,line) )
        {
            int port = stoi(line);
            ports.push_back(port);
        }
        portsfile.close();
    }
    else cout << "Unable to open file"; 

    return ports;
}

vector<string> get_hosts() {
    vector<string> hosts;
    string line;
    ifstream hostsfile (HOSTS_FILE_NAME);
    if (hostsfile.is_open())
    {
        while ( getline (hostsfile,line) )
        {
            hosts.push_back(line);
        }
        hostsfile.close();
    }
    else cout << "Unable to open file"; 

    return hosts;
}