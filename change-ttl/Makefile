build:
	clang --target=bpf -mcpu=v3 -O2 -g -c change-ttl.bpf.c -o change-ttl.o

start: build
	systemctl start tap-mq-pong@tap0.service
	tc qdisc add dev tap0 clsact
	tc filter add dev tap0 egress prio 1 handle 1 bpf da obj change-ttl.o sec classifier
	systemctl start tap-mq-pong@tap0.service

stop:
	systemctl stop tap-mq-pong@tap0.service
	rm change-ttl.o
