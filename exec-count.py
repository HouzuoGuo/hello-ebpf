#!/usr/bin/env python3

import sys
import time
from bcc import BPF

BPF_SOURCE_CODE = r"""
#include <linux/sched.h>
BPF_HASH(execount, char *, unsigned long);
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    char exepath[256] = {0};
    bpf_probe_read_user_str(&exepath, sizeof(exepath), args->filename);
    execount.increment(exepath);
    unsigned long* new_count = execount.lookup(&exepath);
    bpf_trace_printk("exepath: %s\n", exepath);
    return 0;
}
"""

b = BPF(text=BPF_SOURCE_CODE)

print('execve by executable file name')
while True:
    try:
        time.sleep(1)
        # FIXME: of course eBPF won't make string handling easy.
        for k, v in sorted(b["execount"].items(), key=lambda entry: entry[1].value):
            # BUG: the printed file name resembles a user space memory address.
            print(f"Exe file {k}\t\t{v.value}")
        print()
    except KeyboardInterrupt:
        sys.exit()
