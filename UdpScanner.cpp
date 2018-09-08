// udpscan.cpp
#include "UdpScanner.h"

bool UdpScanner::icmp_response(int fd) {
    char buf[1024] = {0};
    struct ip* iphd;
    struct icmp* icmph;

    timeval time_val;
    time_val.tv_sec = 2;
    time_val.tv_usec = 0;
    /* setting them options boy */
    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) != 0)
        cerr << "Oh no spaghettio: could not set socket option" << endl; 

    ssize_t len = recvfrom(fd, &buf, sizeof(buf), 0, NULL, NULL);
    if(len > 0){
        struct ip* iphd = (struct ip*)(buf);
        struct icmp* icmph = (struct icmp*)(buf + iphd->ip_hl*4);

        //Not necessary 
        if((icmph->icmp_type == ICMP_UNREACH) && (icmph->icmp_type == ICMP_UNREACH_PORT))
            return true; // open port
    }
    return false; // closed port
}

void UdpScanner::send_udp_packet(int send_sock, sockaddr_in addr) {
    const char* buf;
    if(sendto(send_sock, buf, 0, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        cerr << "sendto(): failed" << endl;
}

/* UDP scan (ICMP_PORT_UNREACHABLE)*/
void UdpScanner::udp_scan(string host, vector<int> ports) {
    // Open UDP socket to send UDP packet
    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0)
        cerr << "Oh no spaghettio: could not open socket" << endl;
    
    // Open RAW socket to read received packet
    int read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (read_sock < 0)
        cerr << "Oh no spaghettio: could not open socket" << endl;
    
    sockaddr_in addr = get_sockaddr_in(host.c_str(), ports[0]);

    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        addr.sin_port = htons(port);

        send_udp_packet(send_sock, addr);
        bool port_is_closed = icmp_response(read_sock);

        if(!port_is_closed) {
            thread_mutex.lock();
            report[host].push_back(port);
            thread_mutex.unlock();
        }
        int rand_interval = random_number(0, INTERVAL / 5);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL + rand_interval));
    }
}

map<string, list<int>> UdpScanner::udp_scan_range(vector<string> hosts, vector<int> ports) {
    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(&UdpScanner::udp_scan, this, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin(); it != threads.end(); ++it) {
        it->join();
    }
}
