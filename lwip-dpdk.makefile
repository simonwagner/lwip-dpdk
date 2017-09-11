ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

#DPDK config
DPDK_INC=$(DPDK_LIB_PATH)/include
DPDK_LIB=$(DPDK_LIB_PATH)/lib/
DPDK_MACHINE_FLAGS = $(shell cat "$(DPDK_LIB_PATH)/include/cflags.txt") -include $(DPDK_INC)/rte_config.h

RM = rm -f
TARGET_LIB = build/liblwipdpdk.a

SRCS = api.c mempool.c ethif.c \
	port-eth.c context.c rss.c etharp.c etharp_master.c etharp_slave.c

INCLUDES = -I$(ROOT_DIR) \
	-I$(DPDK_INC) \
	-I$(ROOT_DIR)/lwip-contrib/ports/unix/port/include/ \
	-I$(ROOT_DIR)/lwip/src/include/ipv4 \
	-I$(ROOT_DIR)/lwip/src/include

CFLAGS += $(INCLUDES) -L$(DPDK_LIB_PATH) $(DPDK_MACHINE_FLAGS)
LDFLAGS += -ldl -lpthread $(DPDK_LD_FLAGS)

OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	mkdir -p build
	$(AR) rcs $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)