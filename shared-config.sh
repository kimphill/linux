
../scripts/config --set-val CONFIG_LOG_BUF_SHIFT 17
../scripts/config --set-val CONFIG_LOG_CPU_MAX_BUF_SHIFT 15
../scripts/config --set-val CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT 16

../scripts/config -e CONFIG_DEBUG_KMEMLEAK
../scripts/config -e CONFIG_DEBUG_KMEMLEAK_TEST
../scripts/config -e CONFIG_DMA_API_DEBUG

../scripts/config -e CONFIG_DYNAMIC_DEBUG


../scripts/config -e CONFIG_KPROBES
../scripts/config -e CONFIG_KPROBE_EVENTS

../scripts/config -e CONFIG_BPF_SYSCALL
../scripts/config -m CONFIG_TEST_BPF
../scripts/config -e CONFIG_BPF_EVENTS



#exit <<  can't do that here, it exist the caller, maybe try not sourcing this?

#kim@juno perf perf/core$ sudo ./perf test -v bpf

#bpf: config program 'func=do_epoll_wait'
#symbol:do_epoll_wait file:(null) line:0 offset:0 return:0 lazy:(null)
#bpf: config 'func=do_epoll_wait' is ok
#No kprobe blacklist support, ignored
#Looking at the vmlinux_path (8 entries long)
#Using /boot/vmlinux for symbols
#Open Debuginfo file: /boot/vmlinux
#Try to find probe point from debuginfo.
#Matched function: do_epoll_wait [1e8f460]
#Probe point found: do_epoll_wait+0
#Found 1 probe_trace_events.
#Opening /sys/kernel/debug/tracing/kprobe_events write=1
#kprobe_events file does not exist - please rebuild kernel with CONFIG_KPROBE_EVENTS.

