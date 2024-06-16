#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define ETH_P_IP	0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP        
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

bool populate_ip_header(struct iphdr **iphdr, struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return false;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return false;

    *iphdr = data + sizeof(struct ethhdr);
    // unsigned char protocol = 0;
    // protocol = iph->protocol;
    // packet->protocol = ip_header->protocol;
    // bpf_printk("protocol in header=%d", packet->protocol);
    return true;
}

// void readable_ip(unsigned int ip)
// {
//     unsigned char bytes[4];
//     bytes[0] = ip & 0xFF;
//     bytes[1] = (ip >> 8) & 0xFF;
//     bytes[2] = (ip >> 16) & 0xFF;
//     bytes[3] = (ip >> 24) & 0xFF;   
//     sprintf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
// }
// // For TCP or UDP protocols
// if (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP) {
//     uint16_t source_port = ntohs(ip_header->sport); // Convert from network byte order
// } else {
//     // Handle other protocols or non-port-based situations
//     printf("Protocol doesn't have a source port.\n");
// }
