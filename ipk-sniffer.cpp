#include <iostream>
#include <pcap.h> 
#include "Arguments.cpp" 
#include <iomanip>
#include <sstream>
#include <csignal>
#include <ctime>
#include <netdb.h>				
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>	

void printBytes(const u_char *payload, int payload_length) {
    //go through the bytes of the packet. 16 bytes in one line
    for (int j = 0; j < payload_length; j += 16) {
        //print line number
        printf("0x%04x: ", j);
        //output the bytes of the packet
        for (int i = 0; i < 16; ++i) {
            if (j + i < payload_length) {
                printf("%02x ", payload[j + i]);
            } else {
                //print a space if we are at the end of the packet
                printf("   ");
            }
        }
        printf(" ");
        //output ASCII characters
        for (int i = 0; i < 16; ++i) {
            if (j + i < payload_length) {
                //space in the middle
                if(i == 8){
                    printf(" ");
                }
                //print dot instead of a noneprintable symbols 
                if (payload[j + i] >= 33 && payload[j + i] < 127) {
                    printf("%c", payload[j + i]);
                } else {
                    printf(".");
                }
            }
        }
        printf("\n");
    }
}

void print_MAC(struct ether_header *ether_head, bool dst){
    std::stringstream str;
    //set it to hexadecimal output
    str << std::hex << std::setfill('0');
    //loop through bytes of MAC address
    for (int i = 0; i < ETH_ALEN; ++i) {
        //check if it src or dst MAC
        if(dst){
            //convert byte to int and add tp output
            str << std::setw(2) << static_cast<int>(ether_head->ether_dhost[i]);
        }else{
            str << std::setw(2) << static_cast<int>(ether_head->ether_shost[i]);
        }
        //add : between bytes
        if (i < ETH_ALEN - 1) {
            str << ":";
        }
    }
    //print address
    if(dst){
        std::cout << "dst MAC: " << str.str() << std::endl;
    }else{
        std::cout << "src MAC: " << str.str() << std::endl;
    }   
}


//function for cntrl+c processing
pcap_t *handle;

void sigintHandler(int /*signal*/) {
    if (handle != NULL) {
        pcap_close(handle);
    }
    exit(0);
}

//function for packet processing
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    //get time from the packet
    time_t time_sec = pkthdr->ts.tv_sec;
    long time_usec = pkthdr->ts.tv_usec;
    char buffer[40];
    //correct output for data
    int length = strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", localtime(&time_sec)); 

    //adding milliseconds and a time zone identifier
    length += sprintf(buffer + length, ".%03ld", time_usec / 1000);
    char time_z[9];
    strftime(time_z, 10, "%z", localtime(&time_sec));
    sprintf(buffer + length, "%c%c%c:%c%c", time_z[0],time_z[1],time_z[2], time_z[3], time_z[4] );
    std::cout << "timestamp: " << buffer << std::endl;


    //get packet type
    struct ether_header *ether_head = (struct ether_header *) packet;
    int etherType = ntohs(ether_head->ether_type);
    //print src and dst mac address
    print_MAC(ether_head, false);
    print_MAC(ether_head, true);
    
    //get the length of the packet
    int packetLength = pkthdr->len;
    std::cout << "frame length: " << packetLength << " bytes" << std::endl;
    //check packet type
    if (etherType == 0x86DD) { // IPv6
        //get ip6 header
        struct ip6_hdr *ip6_head = (struct ip6_hdr *) (packet + sizeof(struct ether_header));
        //print src and dst IP address
        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_head->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_head->ip6_dst), dst, INET6_ADDRSTRLEN);
        std::cout << "src IP: " << src << std::endl;
        std::cout << "dst IP: " << dst << std::endl;
        //check type of the ip6 packet
        switch (ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
            case IPPROTO_TCP:
            {
                struct tcphdr *header;
                //get tcp header
                header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip6_head->ip6_nxt * 8);
                //print src and dst port for tcp
                std::cout << "src port: " << ntohs(header->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->th_dport) << std::endl;
                //print data
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_UDP:
            {
                struct udphdr *header;
                //get udp header
                header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip6_head->ip6_nxt * 8);
                //print src and dst port for udp
                std::cout << "src port: " << ntohs(header->uh_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->uh_dport) << std::endl;
                //printdata
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_ICMPV6: //for icmp6, mld, ndp
                printBytes(packet, packetLength);
                break;
            default: 
                printBytes(packet, packetLength);
                break;


        }
    } else if (etherType == 0x0800) { // IPv4
        //get ip4 header
        struct ip *ip_head = (struct ip *) (packet + sizeof(struct ether_header));
        //get IO address from header
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_head->ip_src), src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_head->ip_dst), dst, INET_ADDRSTRLEN);
        std::cout << "src IP: " << src << std::endl;
        std::cout << "dst IP: " << dst << std::endl;
        //check type of the ip4 packet
        switch (ip_head->ip_p) {
            case IPPROTO_ICMP:
                //print packet data
                printBytes(packet, packetLength);
                break;
            case IPPROTO_IGMP:
                //print packet data
                printBytes(packet, packetLength);
                break;
            case IPPROTO_TCP:
            {
                //get tcp header
                struct tcphdr *header;
                header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_head->ip_hl * 4);
                //print ports of the packet
                std::cout << "src port: " << ntohs(header->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->th_dport) << std::endl;
                //print data
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_UDP:
            {
                //get udp header
                struct udphdr *header;
                header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_head->ip_hl * 4);
                //print ports
                std::cout << "src port: " << ntohs(header->uh_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->uh_dport) << std::endl;
                //print data
                printBytes(packet, packetLength);
                break;
            }
            default:
                printBytes(packet, packetLength);
                break;
        }
    }else if (etherType == ETHERTYPE_ARP) { //ARP
        //print packet data  
        printBytes(packet, packetLength);
        
    } else {
        //print packet data  
        printBytes(packet, packetLength);
    }
}

int main(int argc, char *argv[]) {
    //variable for filter
    std::string filter_exp;
    //create instance of the argument class
    //constructor parses the arguments 
    Arguments args(argc, argv, filter_exp);
    char errBuffer[1024];
    struct bpf_program fp;
    bpf_u_int32 net, ip_n;
    
    //process cntrl+c signal
    signal(SIGINT, sigintHandler);
    //open a network device to capture packets
    pcap_t *handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errBuffer); 

    if (handle == NULL) {
        fprintf(stderr, "Error pcap open.\n");
        return 1;
    }
    
    
    signal(SIGINT, sigintHandler);
    //check interface
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Error Interface do not support Ethernet." << std::endl;
        return 1;
    }
    //get network parameters for an interface
    if(pcap_lookupnet(args.interface.c_str(), &ip_n, &net, errBuffer) == PCAP_ERROR){
        fprintf(stderr, "Error lookupnet.\n");
        return 1;
    }

    //compile the filter
    //filter_exp was defined when parsing the arguments
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        fprintf(stderr, "Error parse filter.\n");
        return 1;
    }

    //set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error install filter.\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    
    signal(SIGINT, sigintHandler);

    //process packets
    //get the number of packets from the arguments
    pcap_loop(handle, args.num_packets, packetHandler, NULL);

    //release resources
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}