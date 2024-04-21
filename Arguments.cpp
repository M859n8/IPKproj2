#include <iostream>
#include <vector>
#include <string>
#include <getopt.h>
#include <pcap.h> 
class Arguments {
private:
    int source_p; 
    int destination_p;
    int port;
    bool tcp = false, udp = false, arp = false, ndp = false;
    bool icmp4 = false, icmp6 = false, igmp = false, mld = false;

public:
    std::string interface;
    int num_packets = 1;
    // Конструктор класу, який приймає аргументи командного рядка
    Arguments(int argc, char *argv[]) {
        if(argc == 1){
            printInterfaces();
            exit(0);

        }
        for (int i = optind; i < argc; i++) {
            if (std::string(argv[i]) == "-i" || std::string(argv[i]) == "--interface") {

                int check = i+1;
                if(check == argc){
                    //output interfaces
                    std::cout << "interfaces "<< std::endl;
                    printInterfaces();
                    exit(0);
                }
                std::string str = argv[i+1];
                if (str.find('-') == std::string::npos) {
                    interface = argv[i+1];
                    i++;                    
                }

            } else if (std::string(argv[i]) == "-t" || std::string(argv[i]) == "--tcp") {
                tcp = true;
            } else if (std::string(argv[i]) == "-u" || std::string(argv[i]) == "--udp") {

                udp = true;
            } else if (std::string(argv[i]) == "-p" ) {
                port = std::stoi(argv[i+1]);
                i++;
            } else if (std::string(argv[i]) == "--port-destination") {
                destination_p = std::stoi(argv[i+1]);
                i++;
            } else if (std::string(argv[i]) == "--port-source") {
                source_p = std::stoi(argv[i+1]);
                i++;
            } else if (std::string(argv[i]) == "--icmp4") {
                icmp4 = true;
            } else if (std::string(argv[i]) == "--icmp6") {
                icmp6 = true;
            } else if (std::string(argv[i]) == "--arp") {
                arp = true;
            } else if (std::string(argv[i]) == "--ndp") {
                ndp = true;
            }else if (std::string(argv[i]) == "--igmp") {
                igmp = true;
            }else if (std::string(argv[i]) == "--mld") {
                mld = true;
            }else if (std::string(argv[i]) == "-n") {
                num_packets = std::stoi(argv[i+1]);
                i++;
            }else {
                // printUsage();
                //printActiveInterfaces();
                exit(0);
            }
        }
    }

    void printInterfaces() {
    pcap_if_t *allInterface;
    char errbuf[1024];

    // Отримання списку всіх активних мережевих інтерфейсів
    if (pcap_findalldevs(&allInterface, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    // Виведення списку інтерфейсів
    pcap_if_t *interface;
    for (interface = allInterface; interface ; interface = interface->next) {
        std::cout << "  " << interface->name << std::endl;
        
    }

    // Звільнення ресурсів
    pcap_freealldevs(allInterface);
}
    // Метод для виведення використання програми
    // void printUsage() {
    //     std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}" << std::endl;
    //    
    // }
};