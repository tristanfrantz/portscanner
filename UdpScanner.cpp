// udpscan.cpp
#include "UdpScanner.h"

/* UDP scan:
 * Send a udp packet and check if there is an icmp response
 * (or really just any response) to the packet sent
 * if there is a response the packet is closed
 * otherwise it is likely open but could be a false positive
*/
void UdpScanner::udp_scan(string host, vector<int> ports) {
    // Open UDP socket to send UDP packet
    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0)
        cerr << "ERROR could not open socket" << endl;
    
    // Open RAW socket to read received packet
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0)
        cerr << "ERROR could not open socket" << endl;
    
    // Create address for host:port
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        send_udp_packet(send_sock, addr);

        bool port_is_closed = icmp_response(recv_sock);

        if(!port_is_closed) {
            thread_mutex.lock();
            report[host].push_back(port);
            thread_mutex.unlock();
        }
        int rand_interval = random_number(0, INTERVAL / 5);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL + rand_interval));
    }
}

/* Check for icmp response helper function */
bool UdpScanner::icmp_response(int recv_sock) {
    char buf[1024] = {0};
    struct ip* iphd;
    struct icmp* icmph;

    timeval time_val;
    time_val.tv_sec = 2;
    time_val.tv_usec = 0;
    
    /* set receive timeout option to 2 second */
    if(setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) < 0)
        cerr << "ERROR setting socket option" << endl; 

    if(recvfrom(recv_sock, &buf, sizeof(buf), 0, NULL, NULL) > 0){
        struct ip* iphd = (struct ip*)(buf);
        struct icmp* icmph = (struct icmp*)(buf + iphd->ip_hl*4);

        if((icmph->icmp_type == ICMP_UNREACH) && (icmph->icmp_type == ICMP_UNREACH_PORT))
            return true; // open port
    }
    return false; // closed port
}

/* send udp packet helper function */
void UdpScanner::send_udp_packet(int send_sock, sockaddr_in addr) {
    const char* buf;
    if(sendto(send_sock, buf, 0, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        cerr << "ERROR sending packet" << endl;
}


/* Udp scan range of hosts/IPs and return a report of open ports */
map<string, list<int>> UdpScanner::udp_scan_range(vector<string> hosts, vector<int> ports) {
    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(&UdpScanner::udp_scan, this, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin(); it != threads.end(); ++it) {
        it->join();
    }
    return report;
}
