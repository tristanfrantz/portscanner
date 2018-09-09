//stealthscan.cpp
#include "StealthScanner.h"

/* Stealth scan host with the provided random ordered ports.
 * Can be any of the following stealth scans with the corresponding flag/s set:
 * SYN|ACK
 * XMAX (all flags)
 * NULL (no flags)
 * FIN
 *
 * How it works:
 * Send tcp packet with the provided flags and if there is a tcp response with
 * the RST flag set then the port is closed and is added to a set of closed ports.
 * Finally when packets have been sent to all ports, the set of closed ports is
 * compared with the original list of ports. If a port is not in the set of closed
 * ports then that port is assumed to be open.
 *
 * Also: To avoid being detected the thread sleeps for 0.5s + random interval
 * between each send of a packet.
 * 
 * note: the stealth scan produces alof of false positives depending on the setup of the host
 */
void StealthScanner::stealth_scan(string host, vector<int> ports, short flags) {
    /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL */
    int send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
    char source_ip[20];
    get_local_ip( source_ip );
    long source_addr = inet_addr(source_ip);
    long dest_addr = sin.sin_addr.s_addr;
    set<int> closed_ports;
    
    char packet[4096] = {0};
    struct ip *iph = (struct ip *) packet;
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

    
    create_iph(iph, source_addr, dest_addr); // Create the ip header
    create_tcph(tcph, ports[0], flags);      // Create the tcp header
    
    /* Scan the ports */
    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        short port = htons(*it);
        set_tcph_checksum(tcph, source_addr, dest_addr);
        set_tcph_port(tcph, port);

        // Send packet
        if (sendto (send_sock, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            cerr << "ERROR sending packet" << endl;

        // Receiving response packet
        int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        struct timeval time_val;
        time_val.tv_sec = 2;  /* 2 sec Timeout */
        if(setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) < 0)
            cerr << "ERROR setting socket option" << endl;

        char recv_packet[60*1024] = {0};
        recv(recv_sock ,recv_packet, sizeof(recv_packet), 0);

        // Proccess recv packet
        struct ip *iph = (struct ip*)recv_packet;
        long source_addr = iph->ip_src.s_addr;

        if(iph->ip_p == IPPROTO_TCP && source_addr == dest_addr)
        {
            struct tcphdr *tcph=(struct tcphdr*)(recv_packet + iph->ip_hl * 4);

            if(tcph->th_flags == (TH_RST))
            {
                short port = ntohs(tcph->th_sport);
                closed_ports.insert(port);
            }
        }
        int rand_interval = random_number(0, INTERVAL / 5);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL + rand_interval));
    }

    /* iterate through all ports. If the port is not in the closed port set
     * it could be open or filtered
     */
    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        int port = *it;
        const bool is_in = closed_ports.find(port) != closed_ports.end();
        if(!is_in) {
            thread_mutex.lock();
            report[host].push_back(port);
            thread_mutex.unlock();
        }
    }
}

/* Stealth scan range of hosts/IPs and return a report of open ports.
 * Type of scan is depends on the flags varible.
 */
map<string, list<int>> StealthScanner::stealth_scan_range(vector<string> hosts, vector<int> ports, short flags) {
    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(&StealthScanner::stealth_scan, this, host, ports, flags));
    }

    for (vector<thread>::iterator it = threads.begin(); it != threads.end(); ++it) {
        it->join();
    }
    return report;
}
