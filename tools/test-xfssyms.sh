#sudo mkdir /tmp/ramdisk
#sudo mount -t xfs -o size=1024m myramdisk /tmp/ramdisk

dd if=/dev/zero of=fs.img count=0 bs=1 seek=1G
mkfs.xfs fs.img
sudo mount fs.img /mnt

cd /mnt

cat << __EOF | sudo tee usefs.c
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
while (1)
{ int x = open ("xaaaa", O_WRONLY|O_DSYNC|O_CREAT, 0644); write(x, &x, sizeof(int)); fsync(x); close(x); }

return 0;
}
__EOF
sudo gcc -g -o usefs usefs.c
sudo ./usefs &
sudo /home/kim/git/linux-perf-acme-core/tools/perf/perf record -a --call-graph dwarf sleep 1
sudo /home/kim/git/linux-perf-acme-core/tools/perf/perf report --stdio | sudo tee thereport
grep -i \\[k\\] thereport | grep -E xfs_\|0x

sudo killall usefs



exit

     6.28%     0.00%  perf           [kernel.vmlinux]            [k] __sys_trace_return
            |
            ---__sys_trace_return
               |          
               |--4.78%--sys_write
               |          vfs_write
               |          __vfs_write
               |          0xffff2000022952c4
               |          |          
               |           --4.65%--0xffff200002293c58
               |                     iomap_file_buffered_write
               |                     iomap_apply
               |                     iomap_write_actor
               |                     |          


 str = callchain_list__sym_name(chain, bf, sizeof(bf), false);
    
thread__find_addr_location

(gdb) bt
#0  thread__find_addr_location (thread=0x23e83b0, cpumode=2 '\002', type=MAP__FUNCTION, addr=18446497783141192388, al=0xffffffffc398) at util/event.c:1584
#1  0x000000000054a250 in add_callchain_ip (thread=0x23e83b0, cursor=0xffffbeca4700, parent=0xffffffffc6f8, root_al=0xffffffffc690, cpumode=0xffffffffc4c7 "\002,¶T", ip=18446497783141192388, branch=false, flags=0x0, iter=0x0, branch_from=0) at util/machine.c:1782
#2  0x000000000054b3e0 in thread__resolve_callchain_sample (thread=0x23e83b0, cursor=0xffffbeca4700, evsel=0x22e6cb0, sample=0xffffffffc880, parent=0xffffffffc6f8, root_al=0xffffffffc690, max_stack=127) at util/machine.c:2112
#3  0x000000000054b90c in thread__resolve_callchain (thread=0x23e83b0, cursor=0xffffbeca4700, evsel=0x22e6cb0, sample=0xffffffffc880, parent=0xffffffffc6f8, root_al=0xffffffffc690, max_stack=127) at util/machine.c:2221
#4  0x0000000000540768 in sample__resolve_callchain (sample=0xffffffffc880, cursor=0xffffbeca4700, parent=0xffffffffc6f8, evsel=0x22e6cb0, al=0xffffffffc690, max_stack=127) at util/callchain.c:1092
#5  0x00000000005845e8 in hist_entry_iter__add (iter=0xffffffffc6d0, al=0xffffffffc690, max_stack_depth=127, arg=0xffffffffd3a0) at util/hist.c:1042
#6  0x00000000004624a8 in process_sample_event (tool=0xffffffffd3a0, event=0xffffbebea790, sample=0xffffffffc880, evsel=0x22e6cb0, machine=0x22e0018) at builtin-report.c:224
#7  0x00000000005539a0 in perf_evlist__deliver_sample (evlist=0x22e6270, tool=0xffffffffd3a0, event=0xffffbebea790, sample=0xffffffffc880, evsel=0x22e6cb0, machine=0x22e0018) at util/session.c:1242
#8  0x0000000000553b28 in machines__deliver_event (machines=0x22e0018, evlist=0x22e6270, event=0xffffbebea790, sample=0xffffffffc880, tool=0xffffffffd3a0, file_offset=579472) at util/session.c:1279
#9  0x0000000000553ec0 in perf_session__deliver_event (session=0x22dff30, event=0xffffbebea790, sample=0xffffffffc880, tool=0xffffffffd3a0, file_offset=579472) at util/session.c:1342
#10 0x00000000005504b4 in ordered_events__deliver_event (oe=0x22e61d0, event=0x24578d8) at util/session.c:119
#11 0x0000000000557310 in __ordered_events__flush (oe=0x22e61d0) at util/ordered-events.c:210
#12 0x0000000000557638 in ordered_events__flush (oe=0x22e61d0, how=OE_FLUSH__ROUND) at util/ordered-events.c:277
#13 0x0000000000552844 in process_finished_round (tool=0xffffffffd3a0, event=0xffffbebf5270, oe=0x22e61d0) at util/session.c:871
#14 0x0000000000554058 in perf_session__process_user_event (session=0x22dff30, event=0xffffbebf5270, file_offset=623216) at util/session.c:1381
#15 0x00000000005546a4 in perf_session__process_event (session=0x22dff30, event=0xffffbebf5270, file_offset=623216) at util/session.c:1509
#16 0x0000000000555588 in __perf_session__process_events (session=0x22dff30, data_offset=232, data_size=1272896, file_size=1273128) at util/session.c:1901
#17 0x0000000000555770 in perf_session__process_events (session=0x22dff30) at util/session.c:1955
#18 0x00000000004636dc in __cmd_report (rep=0xffffffffd3a0) at builtin-report.c:597
#19 0x0000000000465ff0 in cmd_report (argc=0, argv=0xfffffffff190) at builtin-report.c:1083
#20 0x00000000004eb760 in run_builtin (p=0x9716f0 <commands+240>, argc=2, argv=0xfffffffff190) at perf.c:296
#21 0x00000000004eba14 in handle_internal_command (argc=2, argv=0xfffffffff190) at perf.c:348
#22 0x00000000004ebb88 in run_argv (argcp=0xffffffffef9c, argv=0xffffffffef90) at perf.c:392
#23 0x00000000004ebf1c in main (argc=2, argv=0xfffffffff190) at perf.c:536


break check_weird_callchain_bp
break check_weird_event_bp
break check_weird_map_bp
break check_weird_bp



Run till exit from #0  thread__find_addr_map (thread=0x23e83b0, cpumode=2 '\002', type=MAP__FUNCTION, addr=18446497783141192388, al=0xffffffffc398) at util/event.c:1514
thread__find_addr_location (thread=0x23e83b0, cpumode=2 '\002', type=MAP__FUNCTION, addr=18446497783141192388, al=0xffffffffc398) at util/event.c:1584
(gdb) bt
#0  thread__find_addr_location (thread=0x23e83b0, cpumode=2 '\002', type=MAP__FUNCTION, addr=18446497783141192388, al=0xffffffffc398) at util/event.c:1584
#1  0x000000000054a258 in add_callchain_ip (thread=0x23e83b0, cursor=0xffffbeca4700, parent=0xffffffffc6f8, root_al=0xffffffffc690, cpumode=0xffffffffc4c7 "\002\064¶T", ip=18446497783141192388, branch=false, flags=0x0, iter=0x0, branch_from=0) at util/machine.c:1782
#2  0x000000000054b3e8 in thread__resolve_callchain_sample (thread=0x23e83b0, cursor=0xffffbeca4700, evsel=0x22e6cb0, sample=0xffffffffc880, parent=0xffffffffc6f8, root_al=0xffffffffc690, max_stack=127) at util/machine.c:2112
#3  0x000000000054b914 in thread__resolve_callchain (thread=0x23e83b0, cursor=0xffffbeca4700, evsel=0x22e6cb0, sample=0xffffffffc880, parent=0xffffffffc6f8, root_al=0xffffffffc690, max_stack=127) at util/machine.c:2221
#4  0x0000000000540770 in sample__resolve_callchain (sample=0xffffffffc880, cursor=0xffffbeca4700, parent=0xffffffffc6f8, evsel=0x22e6cb0, al=0xffffffffc690, max_stack=127) at util/callchain.c:1092
#5  0x00000000005846f0 in hist_entry_iter__add (iter=0xffffffffc6d0, al=0xffffffffc690, max_stack_depth=127, arg=0xffffffffd3a0) at util/hist.c:1042
#6  0x00000000004624a8 in process_sample_event (tool=0xffffffffd3a0, event=0xffffbebea790, sample=0xffffffffc880, evsel=0x22e6cb0, machine=0x22e0018) at builtin-report.c:224
#7  0x0000000000553aa8 in perf_evlist__deliver_sample (evlist=0x22e6270, tool=0xffffffffd3a0, event=0xffffbebea790, sample=0xffffffffc880, evsel=0x22e6cb0, machine=0x22e0018) at util/session.c:1242
#8  0x0000000000553c30 in machines__deliver_event (machines=0x22e0018, evlist=0x22e6270, event=0xffffbebea790, sample=0xffffffffc880, tool=0xffffffffd3a0, file_offset=579472) at util/session.c:1279
#9  0x0000000000553fc8 in perf_session__deliver_event (session=0x22dff30, event=0xffffbebea790, sample=0xffffffffc880, tool=0xffffffffd3a0, file_offset=579472) at util/session.c:1342
#10 0x00000000005505bc in ordered_events__deliver_event (oe=0x22e61d0, event=0x24578d8) at util/session.c:119
#11 0x0000000000557418 in __ordered_events__flush (oe=0x22e61d0) at util/ordered-events.c:210
#12 0x0000000000557740 in ordered_events__flush (oe=0x22e61d0, how=OE_FLUSH__ROUND) at util/ordered-events.c:277
#13 0x000000000055294c in process_finished_round (tool=0xffffffffd3a0, event=0xffffbebf5270, oe=0x22e61d0) at util/session.c:871
#14 0x0000000000554160 in perf_session__process_user_event (session=0x22dff30, event=0xffffbebf5270, file_offset=623216) at util/session.c:1381
#15 0x00000000005547ac in perf_session__process_event (session=0x22dff30, event=0xffffbebf5270, file_offset=623216) at util/session.c:1509
#16 0x0000000000555690 in __perf_session__process_events (session=0x22dff30, data_offset=232, data_size=1272896, file_size=1273128) at util/session.c:1901
#17 0x0000000000555878 in perf_session__process_events (session=0x22dff30) at util/session.c:1955
#18 0x00000000004636dc in __cmd_report (rep=0xffffffffd3a0) at builtin-report.c:597
#19 0x0000000000465ff0 in cmd_report (argc=0, argv=0xfffffffff190) at builtin-report.c:1083
#20 0x00000000004eb760 in run_builtin (p=0x9716f0 <commands+240>, argc=2, argv=0xfffffffff190) at perf.c:296
#21 0x00000000004eba14 in handle_internal_command (argc=2, argv=0xfffffffff190) at perf.c:348
#22 0x00000000004ebb88 in run_argv (argcp=0xffffffffef9c, argv=0xffffffffef90) at perf.c:392
#23 0x00000000004ebf1c in main (argc=2, argv=0xfffffffff190) at perf.c:536
(gdb) 

$ pcalc 18446497783239675904   # kernel_start?
	1.844649778323968e+19	0xffff200008081000	0y1111111111111111001000000000000000001000000010000001000000000000
$ pcalc 18446497783273589904
	1.844649778327359e+19	0xffff20000a0d9000	0y1111111111111111001000000000000000001010000011011001000000000000


+static void check_weird_callchain_bp(void)
+{
+               fprintf(stderr, "asdfjkl");
+}
+
+static void check_weird_callchain(u64 ip)
+{
+       if (ip == 0xffff20000230a47cULL ||
+           ip == 0xffff200002293c58ULL ||
+           ip == 0xffff2000022952c4ULL) {
+               check_weird_callchain_bp();
+               //fprintf(stderr, "asdfjkl");
+               //exit(0);
+       }
+}

0xffff200008081000	kernel_start?
0xffff20000230a47c  -> less than kernel_start!
0xffff20000a0d9000	


0xffff20000ad71d1c  legal, valid, working kernel address, darnit

al->addr gets least sig. bits cut off by pcalc: pcalc 0xffff2000022952c4
	1.844649778314119e+19	0xffff200002295000	0y1111111111111111001000000000000000000010001010010101000000000000
al->addr:
$ pcalc 18446497783141192388
	1.844649778314119e+19	0xffff200002295000	0y1111111111111111001000000000000000000010001010010101000000000000


at start of machine__kernel_ip(), kernel_start is uninitialized:
(gdb) print kernel_start
$6 = 281474976694944
(gdb) print ip
$7 = 18446497783141192388

then machine__kernel_start returns cached value from
machine__get_kernel_start(machine), so goodness happens:

(gdb) print kernel_start
$8 = 18446497783239675904
(gdb) print ip
$9 = 18446497783141192388
(gdb) 

now ip is less than kernel_start, and fn returns ip >= kernel_start, so not a
kernel ip (but it is!).  why is that ?  global jump table for these
pointers to fns?:

ssize_t __vfs_write(struct file *file, const char __user *p, size_t count,
		    loff_t *pos)
{
	if (file->f_op->write)
		return file->f_op->write(file, p, count, pos);
	else if (file->f_op->write_iter)
		return new_sync_write(file, p, count, pos);
	else
		return -EINVAL;
}

Ftrace related?

kernel_start is prolly wrong?


int machine__get_kernel_start(struct machine *machine)
{
        struct map *map = machine__kernel_map(machine);
        int err = 0;
    
        /*
         * The only addresses above 2^63 are kernel addresses of a 64-bit
         * kernel.  Note that addresses are unsigned so that on a 32-bit system
         * all addresses including kernel addresses are less than 2^32.  In
         * that case (32-bit system), if the kernel mapping is unknown, all
         * addresses will be assumed to be in user space - see
         * machine__kernel_ip().
         */
        machine->kernel_start = 1ULL << 63;   # 9223372036854775808, 0x8000 0000 0000 0000
        if (map) {
                err = map__load(map);    # returns 0, vmlinux map is loaded
                if (!err)
                        machine->kernel_start = map->start;   # 18446497783239675904, 0xffff200008081000
        }
        return err;
}

what *is* 0xffff20000230a47c  anyway?:


kim@azathoth tools perf/core$ less /sys/module/xfs/sections/
.altinstr_replacement      .fini_array                .note.gnu.build-id         .text.exit
.altinstructions           .fixup                     .ref.data                  .text.startup
.bss                       _ftrace_events             .rodata                    .text.unlikely
__bug_table                .gnu.linkonce.this_module  .rodata.str                __tracepoints
.data                      .init_array                .rodata.str1.8             __tracepoints_ptrs
.data..read_mostly         .init.text                 .strtab                    __tracepoints_strings
.exit.text                 __jump_table               .symtab                    
__ex_table                 __mcount_loc               .text                      
kim@azathoth tools perf/core$ less /sys/module/xfs/sections/.text
kim@azathoth tools perf/core$ sudo cat  /sys/module/xfs/sections/.text
0xffff200002118000

0xffff20000230a47c OK, it is greater than module's .text.

kim@azathoth tools perf/core$ sudo more  /sys/module/xfs/sections/*
::::::::::::::
/sys/module/xfs/sections/__bug_table
::::::::::::::
0xffff200002484458
::::::::::::::
/sys/module/xfs/sections/__ex_table
::::::::::::::
0xffff2000023a8870
::::::::::::::
/sys/module/xfs/sections/_ftrace_events
::::::::::::::
0xffff2000024834e0
::::::::::::::
/sys/module/xfs/sections/__jump_table
::::::::::::::
0xffff2000023a9000
::::::::::::::
/sys/module/xfs/sections/__mcount_loc
::::::::::::::
0xffff2000023a4960
::::::::::::::
/sys/module/xfs/sections/__tracepoints
::::::::::::::
0xffff20000247c220
::::::::::::::
/sys/module/xfs/sections/__tracepoints_ptrs
::::::::::::::
0xffff2000023a39e8
::::::::::::::
/sys/module/xfs/sections/__tracepoints_strings
::::::::::::::
0xffff20000236b3e0
kim@azathoth tools perf/core$   



kim@azathoth tools perf/core$ sudo more  /sys/module/xfs/sections/.*   #'.xxx' -> hidden ones

*** /sys/module/xfs/sections/.: directory ***


*** /sys/module/xfs/sections/..: directory ***

::::::::::::::
/sys/module/xfs/sections/.altinstr_replacement
::::::::::::::
0xffff2000023a87ac
::::::::::::::
/sys/module/xfs/sections/.altinstructions
::::::::::::::
0xffff2000023a8569
::::::::::::::
/sys/module/xfs/sections/.bss
::::::::::::::
0xffff200002484a00
::::::::::::::
/sys/module/xfs/sections/.data
::::::::::::::
0xffff2000023acec0
::::::::::::::
/sys/module/xfs/sections/.data..read_mostly
::::::::::::::
0xffff20000248462c
::::::::::::::
/sys/module/xfs/sections/.exit.text
::::::::::::::
0xffff20000234e560
::::::::::::::
/sys/module/xfs/sections/.fini_array
::::::::::::::
0xffff20000247bf80
::::::::::::::
/sys/module/xfs/sections/.fixup
::::::::::::::
0xffff20000234e378
::::::::::::::
/sys/module/xfs/sections/.gnu.linkonce.this_module
::::::::::::::
0xffff200002484680
::::::::::::::
/sys/module/xfs/sections/.init_array
::::::::::::::
0xffff2000025ab000
::::::::::::::
/sys/module/xfs/sections/.init.text
::::::::::::::
0xffff2000025a0000
::::::::::::::
/sys/module/xfs/sections/.note.gnu.build-id
::::::::::::::
0xffff20000234f000
::::::::::::::
/sys/module/xfs/sections/.ref.data
::::::::::::::
0xffff200002481ef0
::::::::::::::
/sys/module/xfs/sections/.rodata
::::::::::::::
0xffff20000234f080
::::::::::::::
/sys/module/xfs/sections/.rodata.str
::::::::::::::
0xffff2000023a8260
::::::::::::::
/sys/module/xfs/sections/.rodata.str1.8
::::::::::::::
0xffff20000236e3d8
::::::::::::::
/sys/module/xfs/sections/.strtab
::::::::::::::
0xffff200002622698
::::::::::::::
/sys/module/xfs/sections/.symtab
::::::::::::::
0xffff2000025ac000
::::::::::::::
/sys/module/xfs/sections/.text
::::::::::::::
0xffff200002118000
>>>>>>>>>>>>>>>>>>>>>>yes, we're in the .text section: 0xffff20000230a47c OK, it is greater than module's .text.
::::::::::::::
/sys/module/xfs/sections/.text.exit
::::::::::::::
0xffff20000234af90
::::::::::::::
/sys/module/xfs/sections/.text.startup
::::::::::::::
0xffff2000023497d8
::::::::::::::
/sys/module/xfs/sections/.text.unlikely
::::::::::::::
0xffff20000234bcb0


# modules loaded addr with 0xfff... shaved off...not sure if the minus math on these -ve numbers is right:
pcalc 0x230a47c - 0x02118000  
	2040956         	0x1f247c          	0y111110010010001111100

 1f0d60-1f10fc g xfs_log_check_lsn
 1f1110-1f11e8 l xlog_discard_endio_work
 1f11f0-1f1d10 l xlog_cil_committed
 1f1d60-1f2e84 l xlog_cil_push                 <<<< <points here  
 1f2eb0-1f2f1c l xlog_cil_push_work
 1f2f28-1f3074 l xlog_discard_endio
 1f3088-1f3514 l xfs_cil_prepare_item.isra.0
 1f3520-1f369c g xlog_cil_init_post_r

