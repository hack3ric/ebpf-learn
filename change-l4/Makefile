build:
	clang --target=bpf -mcpu=v3 -O2 -g -c change-l4.bpf.c -o change-l4.o

start: build
	systemctl start tap-mq-pong@tap0.service
	tc qdisc add dev tap0 clsact
	tc filter add dev tap0 egress prio 1 handle 1 bpf da obj change-l4.o sec classifier
	tc filter add dev tap0 ingress prio 1 handle 1 bpf da obj change-14.o sec ingress
	systemctl start tap-mq-pong@tap0.service

stop:
	systemctl stop tap-mq-pong@tap0.service
	rm change-ttl.o
