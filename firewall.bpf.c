#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "packet.h"

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 data[4];
};
// https://elixir.bootlin.com/linux/v6.1/source/tools/testing/selftests/bpf/test_lpm_map.c#L331
// https://docs.kernel.org/bpf/map_lpm_trie.html#id1
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // for automatic pinning by xdp-loader
} allow_ipv4 SEC(".maps");

SEC("xdp")
int ping(struct xdp_md *ctx) {
    struct iphdr *iphdr;
    bool success = populate_ip_header(&iphdr, ctx);
    if (!success) {
        bpf_printk("Failed to populate ip header\n");
        return XDP_PASS;
    }
    // long protocol = iphdr->protocol;
    struct ipv4_lpm_key prefix;
    prefix.prefixlen = 32;
    // prefix.data = BPF_CORE_READ(iphdr, saddr);
    bpf_probe_read_kernel(&prefix.data, sizeof(prefix.data), &iphdr->saddr);
    __u32 *ip_match = bpf_map_lookup_elem(&allow_ipv4, &prefix);

    // bpf_printk("ip: %d.%d.%d.%d match:%d\n", prefix.data[0], prefix.data[1], prefix.data[2], prefix.data[3], ip_match);
    if (ip_match == 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
