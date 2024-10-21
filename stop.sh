bpftool net detach xdp dev wlp44s0
rm -f /sys/fs/bpf/hello
rm -f hello.bpf.o hello_usr
rm -f /sys/fs/bpf/xdp_map_count1
