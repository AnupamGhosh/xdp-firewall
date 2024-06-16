#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <string.h>

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 data[4];
};

int map_fd(char *map_name) {
    char map_path[50];
    sprintf(map_path, "/sys/fs/bpf/%s", map_name);
    int fd = bpf_obj_get(map_path);
    if (fd <= 0) {
        printf("Map not found at %s\n", map_path);
        exit(fd);
    }
    return fd;
}

struct ipv4_lpm_key* trie_key(char* ipv4) {
    char* default_prefix = "32";
    char* prefix = strchr(ipv4, '/');
    if (prefix == NULL) {
        prefix = default_prefix;
    } else {
        *prefix = '\0'; // replace '/' with '\0' aka end string
        prefix++; // removes '/'
    }
    struct ipv4_lpm_key *key;
    key = malloc(sizeof(*key));
    // key->data = inet_addr(ipv4);
    inet_pton(AF_INET, ipv4, key->data);
    key->prefixlen = atoi(prefix);
    return key;
}

// `bpftool map dump pinned /sys/fs/bpf/allow_ipv4` shows all the values
// Run this as root
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: myconfig-map <set|del> <key> <value>\n");
        return 1;
    }

    int returncode = -1;
    if (strcmp(argv[1], "allow") == 0) {
        int fd = map_fd("allow_ipv4");
        struct ipv4_lpm_key* ip_cidr = trie_key(argv[2]);
        int ans2all = 42;
        printf("ip: %d.%d.%d.%d prefix:%d\n", ip_cidr->data[0], ip_cidr->data[1], ip_cidr->data[2], ip_cidr->data[3], ip_cidr->prefixlen);
        // printf("ip: %d prefix:%d\n", ip_cidr->data, ip_cidr->prefixlen);
        returncode = bpf_map_update_elem(fd, ip_cidr, &ans2all, BPF_ANY);
    }

    if (returncode == 0) {
        printf("Map updated\n");
    } else {
        printf("Map update failed!\n");
    }
    return returncode;
}