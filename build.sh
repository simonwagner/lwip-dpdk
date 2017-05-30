#!/bin/bash

NUM_CPUS=$(cat /proc/cpuinfo  | grep "processor\\s: " | wc -l)

(
cd ./dpdk
make -j $NUM_CPUS install T=x86_64-native-linuxapp-gcc
)

./configure && make
