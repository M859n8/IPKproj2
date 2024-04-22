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

public:
    std::string interface;
    int num_packets = 1;
    // Конструктор класу, який приймає аргументи командного рядка
    Arguments(int argc, char *argv[], std::string &filter) {
        if(argc == 1){
            printInterfaces();
            exit(0);

        }
        filter = "";
        bool tcp = false;
        bool udp = false;
        bool p = false;
        bool d_port = false;
        bool s_port = false;
        for (int i = optind; i < argc; i++) {
            if (std::string(argv[i]) == "-i" || std::string(argv[i]) == "--interface") {

                int check = i+1;
                if(check == argc){
                    //output interfaces
                    printInterfaces();
                    exit(0);
                }
                std::string str = argv[i+1];
                if (str.find('-') == std::string::npos) {
                    interface = argv[i+1];
                    i++;                    
                }

            } else if (std::string(argv[i]) == "-t" || std::string(argv[i]) == "--tcp") {
                // if (!filter.empty()) {
                //     filter += " or ";
                // }
                // filter += "tcp";
                tcp = true;
            } else if (std::string(argv[i]) == "-u" || std::string(argv[i]) == "--udp") {
                // if (!filter.empty()) {
                //     filter += " or ";
                // }
                // filter += "udp";
                udp = true;
            } else if (std::string(argv[i]) == "-p" ) {
                port = std::stoi(argv[i+1]);
                p = true; 
                // if (!filter.empty()) {
                //     filter += " and ";
                // }
                // filter += "(src port " + std::to_string(port) + " or dst port " + std::to_string(port) + ")";
                i++;
            } else if (std::string(argv[i]) == "--port-destination") {
                destination_p = std::stoi(argv[i+1]);
                d_port = true;
                // if (!filter.empty()) {
                //     filter += " and ";
                // }
                // filter += "dst port " + std::to_string(destination_p);
                i++;
            } else if (std::string(argv[i]) == "--port-source") {
                source_p = std::stoi(argv[i+1]);
                s_port = true;
                // if (!filter.empty()) {
                //     filter += " and ";
                // }
                // filter += "src port " + std::to_string(source_p);
                i++;
            } else if (std::string(argv[i]) == "--icmp4") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "icmp";
            } else if (std::string(argv[i]) == "--icmp6") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "(icmp6 and (icmp6[0] == 128 or icmp6[0] == 129))";
            } else if (std::string(argv[i]) == "--arp") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "arp";
            } else if (std::string(argv[i]) == "--ndp") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "(icmp6 and icmp6[0] >= 133 and icmp6[0] <= 137)";
            }else if (std::string(argv[i]) == "--igmp") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "igmp";
            }else if (std::string(argv[i]) == "--mld") {
                if (!filter.empty()) {
                    filter += " or ";
                }
                filter += "(icmp6 and icmp6[0] >= 130 and icmp6[0] <= 132)";
            }else if (std::string(argv[i]) == "-n") {
                num_packets = std::stoi(argv[i+1]);
                i++;
            }else {
                fprintf(stderr, "Error wrong argument.\n");
                exit(1);
            }

        }
        if(tcp){
            if (!filter.empty()) {
                    filter += " or ";
            }
            filter += "(tcp";
            if(p){
                filter += " and (src port " + std::to_string(port) + " or dst port " + std::to_string(port) + "))";
            }else {
                if(d_port){
                    filter += " and dst port " + std::to_string(destination_p) + ")";
                }
                if(s_port){
                    filter += " and src port " + std::to_string(source_p) + ")";
                }
            }

        }

        if(udp){
            if (!filter.empty()) {
                    filter += " or ";
            }
            filter += "(udp";
            if(p){
                filter += " and (src port " + std::to_string(port) + " or dst port " + std::to_string(port) + "))";
            }else {
                if(d_port){
                    filter += " and dst port " + std::to_string(destination_p) + ")";
                }
                if(s_port){
                    filter += " and src port " + std::to_string(source_p) + ")";
                }
            }

        }
        std::cout << " d  " << filter << std::endl;
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
};