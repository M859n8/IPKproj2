#include <iostream>
#include <pcap.h> 
#include "Arguments.cpp" 
#include <iomanip>
#include <sstream>
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
    for (int j = 0; j < payload_length; j += 16) {
        printf("0x%04x: ", j);
        for (int i = 0; i < 16; ++i) {
            if (j + i < payload_length) {
                printf("%02x ", payload[j + i]);
            } else {
                printf("   ");
            }
        }
        printf(" ");
        for (int i = 0; i < 16; ++i) {
            if (j + i < payload_length) {
                if(i == 8){
                    printf(" ");
                }
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



int i = 0;
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Обробка мережевого пакета
    // Вивід даних пакета, відповідно до вашого формату
    // Отримання часу пакета
    time_t time_sec = pkthdr->ts.tv_sec;
    long time_usec = pkthdr->ts.tv_usec;
    char buffer[40];
    // Форматування дати та часу з мілісекундами
    int length = strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", localtime(&time_sec)); 

    // Додавання мілісекунд та вказівника часового поясу
    length += sprintf(buffer + length, ".%03ld", time_usec / 1000);
    char time_z[9];
    strftime(time_z, 10, "%z", localtime(&time_sec));
    sprintf(buffer + length, "%c%c%c:%c%c", time_z[0],time_z[1],time_z[2], time_z[3], time_z[4] );
    // Вивід часу у форматі RFC 3339
    std::cout << "timestamp: " << buffer << std::endl;

    // Отримання довжини пакета в байтах
    int packetLength = pkthdr->len;
    std::cout << "frame length: " << packetLength << " bytes" << std::endl;

    i++;
    //std::cout << "  i: "<< i<< std::endl;
    // Отримання типу пакета
    // Припустимо, що ми аналізуємо Ethernet та IPv4/IPv6 заголовки
    // Перевіряємо значення типу Ethernet рамки та значення протоколу IPv4/IPv6 заголовка
    struct ether_header *ether_head = (struct ether_header *) packet;
    int etherType = ntohs(ether_head->ether_type);

    std::cout << "src MAC: " << ether_ntoa((const struct ether_addr *)&ether_head->ether_shost) << std::endl;
    std::cout << "dst MAC: " << ether_ntoa((const struct ether_addr *)&ether_head->ether_dhost) << std::endl;
;
    if (etherType == 0x86DD) { // IPv6
        struct ip6_hdr *ip6_head = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_head->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_head->ip6_dst), dst, INET6_ADDRSTRLEN);
        std::cout << "IPv6 Source: " << src << std::endl;
        std::cout << "IPv6 Destination: " << dst << std::endl;

        switch (ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
            case IPPROTO_TCP:
            {
                std::cout << "Packet Type: TCP" << std::endl;
                struct tcphdr *header;
                header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt);

                std::cout << "src port: " << ntohs(header->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->th_dport) << std::endl;
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_UDP:
            {
                std::cout << "Packet Type: UDP" << std::endl;
                struct udphdr *header;
                header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt);

                std::cout << "src port: " << ntohs(header->uh_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->uh_dport) << std::endl;
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_ICMPV6:
                // Додаткова перевірка для розрізнення між ICMPv6 та NDP
                // Перевіряємо, чи пакет є ICMPv6
                if (packet[54] == 128) { // ICMPv6 
                    printBytes(packet, packetLength);
                    std::cout << "6 Packet Type: ICMPv6" << std::endl;
                }else if (packet[54] == 130) { //  MLD 
                    printBytes(packet, packetLength);
                    std::cout << "6 Packet Type: MLD" << std::endl;
                // Перевіряємо, чи пакет є NDP
                }else if (packet[54] == 135) { // NDP 
                    printBytes(packet, packetLength);
                    std::cout << "6 Packet Type: NDP" << std::endl;
                }
                break;
            default: 
                // std::cout << "Packet Type: IPv6 (non-ICMP/IGMP/TCP/UDP)" << std::endl;
                break;


        }
    } else if (etherType == 0x0800) { // IPv4
        struct ip *ip_head = (struct ip *) (packet + sizeof(struct ether_header));

        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_head->ip_src), src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_head->ip_dst), dst, INET_ADDRSTRLEN);
        std::cout << "IP Source: " << src << std::endl;
        std::cout << "IP Destination: " << dst << std::endl;

        switch (ip_head->ip_p) {
            case IPPROTO_ICMP:
                std::cout << "4 Packet Type: ICMPv4" << std::endl;
                printBytes(packet, packetLength);
                break;
            case IPPROTO_IGMP:
                printBytes(packet, packetLength);
                std::cout << "4 Packet Type: IGMP" << std::endl;
                break;
            case IPPROTO_TCP:
            {
                std::cout << "4 Packet Type: TCP" << std::endl;
                // Отримання TCP-заголовка
                struct tcphdr *header;
                header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_head->ip_hl * 4);
                std::cout << "src port: " << ntohs(header->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->th_dport) << std::endl;
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_UDP:
            {
                std::cout << "4 Packet Type: UDP" << std::endl;

                struct udphdr *header;
                header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_head->ip_hl * 4);
                std::cout << "src port: " << ntohs(header->uh_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->uh_dport) << std::endl;
                printBytes(packet, packetLength);

                break;
            }
            default:
                //std::cout << "Packet Type: IPv4 (non-ICMP/IGMP/TCP/UDP)" << std::endl;
                break;
        }
    }else if (etherType == ETHERTYPE_ARP) { //arp
    // }else if (etherType == 1) { 
        std::cout << "Packet Type: ARP" << std::endl;
        printBytes(packet, packetLength);
        
    } else {
        std::cout <<  "Packet Type: Unknown "<< std::endl;
        // std::cout << std::hex << "EtherType: 0x" << etherType << std::endl;
    }
}

int main(int argc, char *argv[]) {
    // Створення об'єкту класу Arguments, що автоматично парсить аргументи командного рядка
    Arguments args(argc, argv);
    char errBuffer[1024];

    // Відкриття мережевого пристрою для захоплення пакетів
    pcap_t *handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errBuffer); 

    if (handle == NULL) {
        std::cerr << "Error pcap open " << errBuffer << std::endl;
        return 1;
    }
    // pcap_t *handle = pcap_open_offline("captured.pcap", errBuffer);
    // if (handle == NULL) {
    //     std::cerr << "Не вдалося відкрити файл для захоплення: " << errBuffer << std::endl;
    //     return 1;
    // }

    // Захоплення та обробка мережевих пакетів
    pcap_loop(handle, args.num_packets, packetHandler, NULL);

    // Закриття мережевого пристрою
    pcap_close(handle);

    return 0;
}