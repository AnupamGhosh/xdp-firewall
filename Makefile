TARGET = firewall
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
NET_INTF = ens4

BPF_OBJ = ${TARGET:=.bpf.o}

# all: config-map
all: $(TARGET) $(BPF_OBJ) config-map
.PHONY: all 
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ) config-map
	xdp-loader unload $(NET_INTF) --all || true
	rm -f /sys/fs/bpf/$(TARGET)
	rm -f /sys/fs/bpf/my_config
	rm -f /sys/fs/bpf/allow_ipv4
	xdp-loader load $(NET_INTF) $(BPF_OBJ) -p /sys/fs/bpf/ -m skb

	./config-map allow "142.250.0.0/15"
	./config-map allow "216.239.32.0/19"
	./config-map allow "169.254.169.254/32"

	./config-map allow "199.232.22.132/32"

	./config-map allow "43.252.250.164/32"

$(BPF_OBJ): %.o: %.c vmlinux.h packet.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -g -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h		

clean:
	- xdp-loader unload $(NET_INTF) --all
	- rm -f /sys/fs/bpf/$(TARGET)
	- rm -f /sys/fs/bpf/my_config
	- rm -f /sys/fs/bpf/allow_ipv4
	- rm $(BPF_OBJ)

config-map: myconfig-map.c
	gcc -Wall -o config-map myconfig-map.c -l:libbpf.a -lelf -lz
