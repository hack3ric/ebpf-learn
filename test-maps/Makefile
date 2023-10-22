build:
	clang --target=bpf -mcpu=v3 -O2 -g -c test-maps.bpf.c -o test-maps.o

start: build
	systemctl start tap-mq-pong@tap0.service
	tc qdisc add dev tap0 clsact
	tc filter add dev tap0 egress prio 1 handle 1 bpf da obj test-maps.o sec egress
	tc filter add dev tap0 ingress prio 1 handle 1 bpf da obj test-maps.o sec ingress
	systemctl start tap-mq-pong@tap0.service

stop:
	systemctl stop tap-mq-pong@tap0.service
	rm /sys/fs/bpf/tc/globals/my_map
	rm test-maps.o
