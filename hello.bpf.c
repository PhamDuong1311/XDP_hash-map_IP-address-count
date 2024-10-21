#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* User define */
#define MAX_ENTRIES 10240

/* Structure for IPv4 address */
struct key_ip {
    __u32 address;  // IPv4 address
};

/* Value structure for counting appearances */
struct value_ip {
    __u64 timesAppearDest;
    __u64 timesAppearSource;
};

/* Define a BPF_MAP_TYPE_HASH for IP addresses */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct key_ip);
    __type(value, struct value_ip);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_map_ip_count SEC(".maps");

/* Update hash map for IP addresses */
static int updateIPAddress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }

    /* Check if it's an IP packet (IPv4) */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return 0;
    }

    /* IPv4 header */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)iph + sizeof(struct iphdr) > data_end) {
        return 0;
    }

    /* Structure to store key (IP address) and value (count) */
    struct key_ip key;
    struct value_ip *value;

    /* Destination IP */
    key.address = iph->daddr;  // Destination IP
    value = bpf_map_lookup_elem(&xdp_map_ip_count, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearDest, 1);
    } else {
        struct value_ip newval = {1, 0};  // Initialize timesAppearDest = 1, timesAppearSource = 0
        bpf_map_update_elem(&xdp_map_ip_count, &key, &newval, BPF_NOEXIST);
    }

    /* Source IP */
    key.address = iph->saddr;  // Source IP
    value = bpf_map_lookup_elem(&xdp_map_ip_count, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearSource, 1);
    } else {
        struct value_ip newval = {0, 1};  // Initialize timesAppearDest = 0, timesAppearSource = 1
        bpf_map_update_elem(&xdp_map_ip_count, &key, &newval, BPF_NOEXIST);
    }

    return XDP_PASS;
}

/* Main XDP handler */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    updateIPAddress(ctx);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

