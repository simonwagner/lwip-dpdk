#!/bin/bash
set -e

NUM_CPUS=$(cat /proc/cpuinfo  | grep "processor\\s: " | wc -l)

make -f lwip.makefile
make -f lwip-dpdk.makefile
make
