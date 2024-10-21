#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>  // For ntohl() and network byte order functions


/* Key structure for IPv4 address */
struct key_ip {
    __u32 address;  // IPv4 address
};

/* Value structure for counting appearances */
struct value_ip {
    __u64 timesAppearDest;
    __u64 timesAppearSource;
};

int main() {
    /* Open the pinned BPF map (assumes it has been pinned at this location) */
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_map_ip_count"); // Path to pinned map
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct key_ip cur_key = {};
    struct key_ip next_key;
    struct value_ip val;

    /* Continuously traverse the map and print its contents */
    while (1) {
        cur_key = (struct key_ip) {}; // Reset the current key
        
        /* Traverse the map using bpf_map_get_next_key() and bpf_map_lookup_elem() */
        while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                /* Convert the IP address from network to host byte order */
                __u32 ip = ntohl(next_key.address);

                /* Print the IP address in human-readable form */
                printf("IP Address %u.%u.%u.%u, Times Dest %llu, Times Src %llu\n",
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF, ip & 0xFF,
                       val.timesAppearDest, val.timesAppearSource);
            }
            cur_key = next_key;  // Move to the next key
        }
        printf("\n----------------------\n");
        sleep(1);  // Wait for 1 second before the next iteration
    }

    close(map_fd);
    return 0;
}

