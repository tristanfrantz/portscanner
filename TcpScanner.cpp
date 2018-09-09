// tcpscan.cpp
#include "TcpScanner.h"

/* TCP open scan host with provided random ordered ports.
 * By doing a connect to the host:port initiating a 3-way handshake
 * If successful the port is open on the host otherwise it's not.
 * 
 * Also: To avoid being detected the thread sleeps for 0.5s + random interval
 * between each send of a packet.
 */
void TcpScanner::tcp_scan(string host, vector<int> ports) {
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        bool port_is_open = connect_to_host(addr);
        if (port_is_open) {
            thread_mutex.lock();
            report[host].push_back(port);
            thread_mutex.unlock();
        }
        int rand_interval = random_number(0, INTERVAL / 5);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL));
    }
}

/* Check if connection is successful via connect to host:port
 * return true if connection was a success
 * else return false
 */
bool TcpScanner::connect_to_host(struct sockaddr_in serv_addr) {
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

/* Tcp connect scan range of hosts/IPs and return a report of open ports */
map<string, list<int>> TcpScanner::tcp_scan_range(vector<string> hosts, vector<int> ports) {
    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(&TcpScanner::tcp_scan, this, host, ports));
        this_thread::sleep_for (chrono::milliseconds(10));
    }

    for (vector<thread>::iterator it = threads.begin(); it != threads.end() ; ++it) {
        it->join();
    }
    return report;
}