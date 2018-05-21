# arm-cs-trace-disasm.py: ARM CoreSight Trace Dump With Disassember
# SPDX-License-Identifier: GPL-2.0
#
# Tor Jeremiassen <tor@ti.com> is original author who wrote script
# skeleton, Mathieu Poirier <mathieu.poirier@linaro.org> contributed
# fixes for build-id and memory map; Leo Yan <leo.yan@linaro.org>
# updated the packet parsing with new samples format.

import os
import sys
import re
from subprocess import *
from optparse import OptionParser, make_option

# Command line parsing

option_list = [
	# formatting options for the bottom entry of the stack
	make_option("-k", "--vmlinux", dest="vmlinux_name",
		    help="Set path to vmlinux file"),
	make_option("-d", "--objdump", dest="objdump_name",
		    help="Set path to objdump executable file"),
	make_option("-v", "--verbose", dest="verbose",
		    action="store_true", default=False,
		    help="Enable debugging log")
]

parser = OptionParser(option_list=option_list)
(options, args) = parser.parse_args()

if (options.objdump_name == None):
	sys.exit("No objdump executable file specified - use -d or --objdump option")

# Initialize global dicts and regular expression

build_ids = dict()
mmaps = dict()
disasm_cache = dict()
cpu_data = dict()
disasm_re = re.compile("^\s*([0-9a-fA-F]+):")
disasm_func_re = re.compile("^\s*([0-9a-fA-F]+)\s\<.*\>:")
cache_size = 32*1024
prev_cpu = -1

def parse_buildid():
	global build_ids

	buildid_regex = "([a-fA-f0-9]+)[ \t]([^ \n]+)"
	buildid_re = re.compile(buildid_regex)

	results = check_output(["perf", "buildid-list"]).split('\n');
	for line in results:
		m = buildid_re.search(line)
		if (m == None):
			continue;

		id_name = m.group(2)
		id_num  = m.group(1)

		if (id_name == "[kernel.kallsyms]") :
			append = "/kallsyms"
		elif (id_name == "[vdso]") :
			append = "/vdso"
		else:
			append = "/elf"

		build_ids[id_name] = os.environ['PERF_BUILDID_DIR'] + \
					"/" + id_name + "/" + id_num + append;
		# Replace duplicate slash chars to single slash char
		build_ids[id_name] = build_ids[id_name].replace('//', '/', 1)

	if ((options.vmlinux_name == None) and ("[kernel.kallsyms]" in build_ids)):
		print "kallsyms cannot be used to dump assembler"

	# Set vmlinux path to replace kallsyms file, if without buildid we still
	# can use vmlinux to prase kernel symbols
	if ((options.vmlinux_name != None)):
		build_ids['[kernel.kallsyms]'] = options.vmlinux_name;

def parse_mmap():
	global mmaps

	# Check mmap for PERF_RECORD_MMAP and PERF_RECORD_MMAP2
	mmap_regex = "PERF_RECORD_MMAP.* -?[0-9]+/[0-9]+: \[(0x[0-9a-fA-F]+)\((0x[0-9a-fA-F]+)\).*:\s.*\s(\S*)"
	mmap_re = re.compile(mmap_regex)

	results = check_output("perf script --show-mmap-events | fgrep PERF_RECORD_MMAP", shell=True).split('\n')
	for line in results:
		m = mmap_re.search(line)
		if (m != None):
			if (m.group(3) == '[kernel.kallsyms]_text'):
				dso = '[kernel.kallsyms]'
			else:
				dso = m.group(3)

			start = int(m.group(1),0)
			end   = int(m.group(1),0) + int(m.group(2),0)
			mmaps[dso] = [start, end]

def find_dso_mmap(addr):
	global mmaps

	for key, value in mmaps.items():
		if (addr >= value[0] and addr < value[1]):
			return key

	return None

def read_disam(dso, start_addr, stop_addr):
	global mmaps
	global build_ids

	addr_range = start_addr  + ":" + stop_addr;

	# Don't let the cache get too big, clear it when it hits max size
	if (len(disasm_cache) > cache_size):
		disasm_cache.clear();

	try:
		disasm_output = disasm_cache[addr_range];
	except:
		try:
			fname = build_ids[dso];
		except KeyError:
			sys.exit("cannot find symbol file for " + dso)

		disasm = [ options.objdump_name, "-d", "-z",
			   "--start-address="+start_addr,
			   "--stop-address="+stop_addr, fname ]

		disasm_output = check_output(disasm).split('\n')
		disasm_cache[addr_range] = disasm_output;

	return disasm_output

def dump_disam(dso, start_addr, stop_addr, check_svc):
	for line in read_disam(dso, start_addr, stop_addr):
		m = disasm_func_re.search(line)
		if (m != None):
			print "\t",line
			continue

		m = disasm_re.search(line)
		if (m == None):
			continue;

		print "\t",line

		if ((check_svc == True) and "svc" in line):
			return

def dump_packet(sample):
	print "Packet = { cpu: 0x%d addr: 0x%x phys_addr: 0x%x ip: 0x%x " \
	      "pid: %d tid: %d period: %d time: %d }" % \
	      (sample['cpu'], sample['addr'], sample['phys_addr'], \
	       sample['ip'], sample['pid'], sample['tid'], \
	       sample['period'], sample['time'])

def trace_begin():
	print 'ARM CoreSight Trace Data Assembler Dump'
	parse_buildid()
	parse_mmap()

def trace_end():
	print 'End'

def trace_unhandled(event_name, context, event_fields_dict):
	print ' '.join(['%s=%s'%(k,str(v))for k,v in sorted(event_fields_dict.items())])

def process_event(param_dict):
	global cache_size
	global options
	global prev_cpu

	sample = param_dict["sample"]

	if (options.verbose == True):
		dump_packet(sample)

	# If period doesn't equal to 1, this packet is for instruction sample
	# packet, we need drop this synthetic packet.
	if (sample['period'] != 1):
		print "Skip synthetic instruction sample"
		return

	cpu = format(sample['cpu'], "d");

	# Initialize CPU data if it's empty, and directly return back
	# if this is the first tracing event for this CPU.
	if (cpu_data.get(str(cpu) + 'addr') == None):
		cpu_data[str(cpu) + 'addr'] = format(sample['addr'], "#x")
		prev_cpu = cpu
		return

	# The format for packet is:
	#
	#                 +------------+------------+------------+
	#  sample_prev:   |    addr    |    ip      |    cpu     |
	#                 +------------+------------+------------+
	#  sample_next:   |    addr    |    ip      |    cpu     |
	#                 +------------+------------+------------+
	#
	# We need to combine the two continuous packets to get the instruction
	# range for sample_prev::cpu:
	#
	#     [ sample_prev::addr .. sample_next::ip ]
	#
	# For this purose, sample_prev::addr is stored into cpu_data structure
	# and read back for 'start_addr' when the new packet comes, and we need
	# to use sample_next::ip to calculate 'stop_addr', plusing extra 4 for
	# 'stop_addr' is for the sake of objdump so the final assembler dump can
	# include last instruction for sample_next::ip.

	start_addr = cpu_data[str(prev_cpu) + 'addr']
	stop_addr  = format(sample['ip'] + 4, "#x")

	# Sanity checking dso for start_addr and stop_addr
	prev_dso = find_dso_mmap(int(start_addr, 0))
	next_dso = find_dso_mmap(int(stop_addr, 0))

	# If cannot find dso so cannot dump assembler, bail out
	if (prev_dso == None or next_dso == None):
		print "Address range [ %s .. %s ]: failed to find dso" % (start_addr, stop_addr)
		prev_cpu = cpu
		return
	elif (prev_dso != next_dso):
		print "Address range [ %s .. %s ]: isn't in same dso" % (start_addr, stop_addr)
		prev_cpu = cpu
		return

	dump_disam(prev_dso, start_addr, stop_addr, False)

	cpu_data[str(cpu) + 'addr'] = format(sample['addr'], "#x")
	prev_cpu = cpu
