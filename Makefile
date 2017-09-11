ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

#DPDK config
DPDK_INC=$(DPDK_LIB_PATH)/include
DPDK_LIB=$(DPDK_LIB_PATH)/lib/
DPDK_LD_FLAGS=$(shell cat "$(DPDK_LIB_PATH)/lib/ldflags.txt")
DPDK_MACHINE_FLAGS=$(shell cat "$(DPDK_LIB_PATH)/include/cflags.txt") -include $(DPDK_INC)/rte_config.h

LDFLAGS += $(DPDK_MACHINE_FLAGS) $(DPDK_LD_FLAGS) -L$(ROOT_DIR)build -llwipdpdk -lpthread
RM = rm -f
TARGET = build/lwip-dpdk

SRCS_C = tools.c
SRCS_CXX = main.cpp

INCLUDES = -I$(ROOT_DIR) \
	-I$(DPDK_INC) \
	-I$(ROOT_DIR)/lwip-contrib/ports/unix/port/include/ \
	-I$(ROOT_DIR)/lwip/src/include/ipv4 \
	-I$(ROOT_DIR)/lwip/src/include

CFLAGS += $(INCLUDES) -L$(DPDK_LIB_PATH) $(DPDK_MACHINE_FLAGS)
CXXFLAGS += $(INCLUDES) -L$(DPDK_LIB_PATH) $(DPDK_MACHINE_FLAGS)

OBJS = $(SRCS_C:.c=.o) $(SRCS_CXX:.cpp=.o)

.PHONY: all
all: ${TARGET}

$(TARGET): $(OBJS)
	mkdir -p build
	$(CXX) $^ ${LDFLAGS} -o $@

$(SRCS_C:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

$(SRCS_CXX:.cpp=.d):%.d:%.cpp
	$(CXX) $(CFLAGS) -MM $< >$@

include $(SRCS_C:.c=.d)
include $(SRCS_CXX:.cpp=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET} ${OBJS} $(SRCS_C:.c=.d) $(SRCS_CXX:.cpp=.d)