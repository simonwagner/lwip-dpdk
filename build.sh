#!/bin/bash

NUM_CPUS=$(cat /proc/cpuinfo  | grep "processor\\s: " | wc -l)

make -f lwip.makefile
make
