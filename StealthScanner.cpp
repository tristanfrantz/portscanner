//stealthscan.cpp
#include "StealthScanner.h"

/* stealth scan host with the provided random ordered ports
 * can be any of the following stealth scans with the corresponding flag/s set:
 * SYN|ACK
 * XMAX (all flags)
 * NULL (no flags)
 * FIN
 * note: the stealth scan produces false positives
 */
void StealthScanner::stealth_scan(string host, vector<int> ports, short flags){
  /* A protocol of IPPROTO_RAW implies enabled IP_HDRINCL */
  int send_sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  struct sockaddr_in sin = get_sockaddr_in(host.c_str(), ports[0]);
    char source_ip[20];
    get_local_ip( source_ip );
    long source_addr = inet_addr(source_ip);
  long dest_addr = sin.sin_addr.s_addr;
  
  char packet[4096] = {0};
  struct ip *iph = (struct ip *) packet;
  struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));

  /* create the ip header */
  create_iph(iph, source_addr, dest_addr);

  /* create the tcp header */
  create_tcph(tcph, ports[0], flags);

  /* scan random-ordered ports */
  set<int> closed_ports;
  for(vector<int>::iterator it = ports.begin(); it != ports.end(); ++it) {
    short port = htons(*it);
    set_tcph_checksum(tcph, source_addr, dest_addr);
    set_tcph_port(tcph, port);

    // Sending packet
    if (sendto (send_sock, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        cout << "error sending packet" << endl;
        return;
    }

    // Receiving response packet
    int read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct timeval tv;
    tv.tv_sec = 2;  /* 2 sec Timeout */
    setsockopt(read_sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

    char recv_packet[60*1024] = {0};
    recv(read_sock ,recv_packet, sizeof(recv_packet), 0);

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

/* Stealth scan range of IPs with the provided random ordered ports */
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
