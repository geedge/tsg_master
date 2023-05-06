#include <linux/if_ether.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <gtest/gtest.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>

#include "tsg_proxy.h"

TEST(IPV4, tcp_opt_parse)
{
    struct pkt_info pktinfo;
    struct tsg_proxy_tcp_attribute tcp_attr;
    pcap_t *pcap_file_fd = NULL;
    struct pcap_pkthdr *header; // pcap报文头部结构
    const u_char *packet; // 报文数据指针
    struct iphdr *ip; // ip头部结构
    struct streaminfo stream;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_file_fd = pcap_open_offline("pcap/ipv4_ssl_handshake.pcapng", errbuf);
    ASSERT_TRUE(pcap_file_fd != NULL);

    //syn
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip = (struct iphdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv4_header_parse((void *)ip, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);
    ASSERT_EQ(tcp_attr.tcp_opt_client.mss, 1460);
    ASSERT_EQ(tcp_attr.tcp_opt_client.wscale_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.wscale, 8);
    ASSERT_EQ(tcp_attr.tcp_opt_client.sack, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_val, ntohl(619788329));
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_ecr, 0);
    ASSERT_EQ(tcp_attr.tcp_opt_client.window, 64240);

    //syn&ack
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip = (struct iphdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv4_header_parse((void *)ip, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);
    ASSERT_EQ(tcp_attr.tcp_opt_server.mss, 1460);
    ASSERT_EQ(tcp_attr.tcp_opt_server.wscale_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.wscale, 8);
    ASSERT_EQ(tcp_attr.tcp_opt_server.sack, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_val, ntohl(201296612));
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_ecr, ntohl(619788329));
    ASSERT_EQ(tcp_attr.tcp_opt_server.window, 65535);

    //ack
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip = (struct iphdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv4_header_parse((void *)ip, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);

    //first data pkt
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip = (struct iphdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv4_header_parse((void *)ip, &pktinfo);
    stream.curdir = DIR_C2S;
    tsg_proxy_first_data_process(&stream, &tcp_attr, &pktinfo);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_val, ntohl(619788360));
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_val, ntohl(201296612));
    ASSERT_EQ(tcp_attr.tcp_seq, ntohl(265573753));
    ASSERT_EQ(tcp_attr.tcp_ack, ntohl(2286004672));
    ASSERT_EQ(tcp_attr.tcp_info_packet_cur_dir, DIR_C2S);

    pcap_close(pcap_file_fd);
}

TEST(IPV6, tcp_opt_parse)
{
    struct pkt_info pktinfo;
    struct tsg_proxy_tcp_attribute tcp_attr;
    pcap_t *pcap_file_fd = NULL;
    struct pcap_pkthdr *header; // pcap报文头部结构
    const u_char *packet; // 报文数据指针
    struct ip6_hdr *ip6; // ip头部结构
    struct streaminfo stream;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_file_fd = pcap_open_offline("pcap/ipv6_ssl_handshake.pcapng", errbuf);
    ASSERT_TRUE(pcap_file_fd != NULL);

    //syn
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip6 = (struct ip6_hdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv6_header_parse((void *)ip6, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);
    ASSERT_EQ(tcp_attr.tcp_opt_client.mss, 1440);
    ASSERT_EQ(tcp_attr.tcp_opt_client.wscale_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.wscale, 8);
    ASSERT_EQ(tcp_attr.tcp_opt_client.sack, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_val, ntohl(619788492));
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_ecr, 0);
    ASSERT_EQ(tcp_attr.tcp_opt_client.window, 64800);

    //syn&ack
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip6 = (struct ip6_hdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv6_header_parse((void *)ip6, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);
    ASSERT_EQ(tcp_attr.tcp_opt_server.mss, 1440);
    ASSERT_EQ(tcp_attr.tcp_opt_server.wscale_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.wscale, 8);
    ASSERT_EQ(tcp_attr.tcp_opt_server.sack, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_set, 1);
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_val, ntohl(1014079587));
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_ecr, ntohl(619788492));
    ASSERT_EQ(tcp_attr.tcp_opt_server.window, 65535);

    //ack
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip6 = (struct ip6_hdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv6_header_parse((void *)ip6, &pktinfo);
    tsg_proxy_tcp_parse(&tcp_attr, &pktinfo, &stream);

    //first data pkt
    ASSERT_TRUE(pcap_next_ex(pcap_file_fd, &header, &packet) >= 0);
    ip6 = (struct ip6_hdr*) (packet + sizeof(struct ethhdr));
    tsg_proxy_ipv6_header_parse((void *)ip6, &pktinfo);
    stream.curdir = DIR_C2S;
    tsg_proxy_first_data_process(&stream, &tcp_attr, &pktinfo);
    ASSERT_EQ(tcp_attr.tcp_opt_client.ts_val, ntohl(619788540));
    ASSERT_EQ(tcp_attr.tcp_opt_server.ts_val, ntohl(1014079587));
    ASSERT_EQ(tcp_attr.tcp_seq, ntohl(625826589));
    ASSERT_EQ(tcp_attr.tcp_ack, ntohl(64211095));
    ASSERT_EQ(tcp_attr.tcp_info_packet_cur_dir, DIR_C2S);

    pcap_close(pcap_file_fd);
}

int main(int argc, char *argv[])
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}