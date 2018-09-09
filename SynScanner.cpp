#include "SynScanner.h"

/* Syn scan host with the provided random ordered ports.
 * 
 * How it works:
 * Start off by sending packet with the syn flag set.
 * A constantly running packet sniffer sniffs for a syn-ack response
 * If the address of the syn-ack response matches the provided host address
 * Then that port is open otherwise it's closed.
 * 
 * Also: To avoid being detected the thread sleeps for 0.5s + random interval
 * between each send of a packet.
 */
void SynScanner::syn_scan(string host, vector<int> ports) {
    /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL */
    int send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0)
        cerr << "ERROR opening socket" << endl;

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0)
        cerr << "ERROR opening socket" << endl;

    struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
    char source_ip[20];
    get_local_ip( source_ip );
    long source_addr = inet_addr(source_ip);
    long dest_addr = sin.sin_addr.s_addr;
    short flags = TH_SYN;

    char packet[4096] = {0};
    struct ip *iph = (struct ip *) packet;
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

    /* create the ip header */
    create_iph(iph, source_addr, dest_addr);

    /* create the tcp header */
    create_tcph(tcph, ports[0], flags);

    /* start the sniffing machine */
    thread sniff(&SynScanner::packet_sniffer, this, recv_sock, dest_addr, host);

    /* Send packets to host:port with the syn flag set */
    for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
        short port = *it;
        set_tcph_port(tcph, port);
        set_tcph_checksum(tcph, source_addr, dest_addr);

        if (sendto (send_sock, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            cerr << "ERROR sending packet" << endl;

        int rand_interval = random_number(0, INTERVAL / 5);
        this_thread::sleep_for (chrono::milliseconds(INTERVAL + rand_interval));
    }
    sniff.detach();
    close(recv_sock);
}

/* Helper function for packet_sniffer
 * That check if a received packet:
 * 1. Is using the tcp protocol
 * 2. Is from the host address
 * 3. Has syn|ack flags set
 */
bool SynScanner::syn_ack_response(char* recv_packet, long dest_addr) {
    struct ip *iph = (struct ip*)recv_packet;
    char iph_protocol = iph->ip_p;
    long source_addr = iph->ip_src.s_addr;
    int iph_size = iph->ip_hl*4;


    if(iph_protocol == IPPROTO_TCP &&source_addr == dest_addr) {
        struct tcphdr *tcph=(struct tcphdr*)(recv_packet + iph_size);
        if(tcph->th_flags == (TH_SYN|TH_ACK))
            return true;
    }
    return false;
}

/* Packet sniffer to check for SYN-ACK response */
void SynScanner::packet_sniffer(int recv_sock, long dest_addr, string host) {
    while(true)
    {
        char recv_packet[4096] = {0};
        recv(recv_sock ,recv_packet, sizeof(recv_packet), 0);

        bool port_is_open = syn_ack_response(recv_packet, dest_addr);

        if (port_is_open) {
            struct tcphdr *tcph=(struct tcphdr*)(recv_packet + sizeof(struct ip));

            int port = ntohs(tcph->th_sport);
            thread_mutex.lock();
            report[host].push_back(port);
            thread_mutex.unlock();
        }
    }
}

/* Syn scan range of hosts/IPs and return a report of open ports */
map<string, list<int>> SynScanner::syn_scan_range(vector<string> hosts, vector<int> ports) {
    for(vector<string>::iterator it = hosts.begin(); it != hosts.end(); ++it) {
        string host = *it;
        threads.push_back(thread(&SynScanner::syn_scan, this, host, ports));
    }

    for (vector<thread>::iterator it = threads.begin(); it != threads.end(); ++it) {
        it->join();
    }

    return report;
}