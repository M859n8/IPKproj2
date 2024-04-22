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
void print_MAC(struct ether_header *ether_head, bool dst){
    std::stringstream str;
    //налаштовуємо його на шістнадцятковий вивід та заповнюємо ведучі нулі 
    str << std::hex << std::setfill('0');
    //Ми проходимо по кожному байту MAC-адреси ether_shost, конвертуючи його до шістнадцяткового числа, і додаємо його до std::stringstream
    for (int i = 0; i < ETH_ALEN; ++i) {
        if(dst){
//ми використовуємо static_cast, щоб перетворити значення байту MAC-адреси на ціле число типу int.
//Це необхідно, оскільки std::setw() очікує, що ви передаєте ціле число. Байт має тип unsigned char, але std::setw() очікує тип int.
            str << std::setw(2) << static_cast<int>(ether_head->ether_dhost[i]);
        }else{
            str << std::setw(2) << static_cast<int>(ether_head->ether_shost[i]);
        }
        // Після цього ми додаємо роздільник ":" між кожним байтом, за винятком останнього.
        if (i < ETH_ALEN - 1) {
            str << ":";
        }
    }
    if(dst){
        std::cout << "dst MAC: " << str.str() << std::endl;
    }else{
        std::cout << "src MAC: " << str.str() << std::endl;
    }   
}



pcap_t *handle;

void sigintHandler(int /*signal*/) {
    if (handle != NULL) {
        pcap_close(handle);
    }
    exit(0);
}


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

    // Отримання типу пакета
    // Припустимо, що ми аналізуємо Ethernet та IPv4/IPv6 заголовки
    // Перевіряємо значення типу Ethernet рамки та значення протоколу IPv4/IPv6 заголовка
    struct ether_header *ether_head = (struct ether_header *) packet;
    int etherType = ntohs(ether_head->ether_type);

    print_MAC(ether_head, false);
    print_MAC(ether_head, true);
;
    if (etherType == 0x86DD) { // IPv6
        struct ip6_hdr *ip6_head = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_head->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_head->ip6_dst), dst, INET6_ADDRSTRLEN);
        std::cout << "src IP: " << src << std::endl;
        std::cout << "dst IP: " << dst << std::endl;

        switch (ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
            case IPPROTO_TCP:
            {
                //std::cout << "Packet Type: TCP" << std::endl;
                struct tcphdr *header;
                header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip6_head->ip6_ctlun.ip6_un1.ip6_un1_nxt);

                std::cout << "src port: " << ntohs(header->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(header->th_dport) << std::endl;
                printBytes(packet, packetLength);
                break;
            }
            case IPPROTO_UDP:
            {
                //std::cout << "Packet Type: UDP" << std::endl;
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
                // if (packet[54] == 128) { // ICMPv6 
                //     printBytes(packet, packetLength);
                //     //std::cout << "6 Packet Type: ICMPv6" << std::endl;
                // }else if (packet[54] == 130) { //  MLD 
                //     printBytes(packet, packetLength);
                //     //std::cout << "6 Packet Type: MLD" << std::endl;
                // // Перевіряємо, чи пакет є NDP
                // }else if (packet[54] == 135) { // NDP 
                //     printBytes(packet, packetLength);
                //     //std::cout << "6 Packet Type: NDP" << std::endl;
                // }else{
                    printBytes(packet, packetLength);

                // }
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
        std::cout << "src IP: " << src << std::endl;
        std::cout << "dst IP: " << dst << std::endl;

        switch (ip_head->ip_p) {
            case IPPROTO_ICMP:
                //std::cout << "4 Packet Type: ICMPv4" << std::endl;
                printBytes(packet, packetLength);
                break;
            case IPPROTO_IGMP:
                printBytes(packet, packetLength);
                //std::cout << "4 Packet Type: IGMP" << std::endl;
                break;
            case IPPROTO_TCP:
            {
                //std::cout << "4 Packet Type: TCP" << std::endl;
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
                //std::cout << "4 Packet Type: UDP" << std::endl;

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
    //  }else if (etherType == 1) { 
        //std::cout << "Packet Type: ARP" << std::endl;
        printBytes(packet, packetLength);
        
    } else {
        fprintf(stderr, "Error packet type.\n");
        // std::cout << std::hex << "EtherType: 0x" << etherType << std::endl;
    }
}

int main(int argc, char *argv[]) {
    std::string filter_exp; // Фільтр для захоплення пакетів TCP
    // Створення об'єкту класу Arguments, що автоматично парсить аргументи командного рядка
    Arguments args(argc, argv, filter_exp);
    char errBuffer[1024];
    struct bpf_program fp;
    //bpf_u_int32 net;
    // Встановлюємо обробник сигналу для SIGINT (Ctrl+C)
    signal(SIGINT, sigintHandler);
    //printf("2Filter expression: %s\n", filter_exp.c_str());
    // Відкриття мережевого пристрою для захоплення пакетів
    pcap_t *handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errBuffer); 

    if (handle == NULL) {
        fprintf(stderr, "Error pcap open.\n");
        return 1;
    }
    // Встановлюємо обробник сигналу для SIGINT (Ctrl+C)
    signal(SIGINT, sigintHandler);
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Error Interface do not support Ethernet." << std::endl;
        return 1;
    }

    // Компіляція фільтра
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error parse filter.\n");
        return 1;
    }

    // Встановлення скомпільованого фільтра
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error install filter.\n");
        return 1;
    }
    // Встановлюємо обробник сигналу для SIGINT (Ctrl+C)
    signal(SIGINT, sigintHandler);
    // Захоплення та обробка мережевих пакетів
    pcap_loop(handle, args.num_packets, packetHandler, NULL);

    // Закриття мережевого пристрою
    pcap_close(handle);

    return 0;
}