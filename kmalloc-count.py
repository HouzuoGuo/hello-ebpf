#!/usr/bin/env python3

import sys
import time
from bcc import BPF

BPF_SOURCE_CODE = r"""
BPF_HASH(callers, u64, unsigned long);
TRACEPOINT_PROBE(kmem, kmalloc) {
    u64 ip = args->call_site;
    unsigned long new_count = 1;
    unsigned long* existing_count = callers.lookup((u64*)&ip);
    if (existing_count != 0) {
        new_count = *existing_count + 1;
    }
    callers.update(&ip, &new_count);
    return 0;
}
"""

b = BPF(text=BPF_SOURCE_CODE)

print('kmalloc count by caller')
while True:
    try:
        time.sleep(1)
        for k, v in sorted(b["callers"].items(), key=lambda entry: entry[1].value):
            print(f"Caller {b.ksym(k.value)}\t\t{v.value}")
        print()
    except KeyboardInterrupt:
        sys.exit()
