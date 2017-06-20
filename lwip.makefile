ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS ?= -Wall -Wextra -O2 -g
CFLAGS += -fPIC
LDFLAGS += -shared
RM = rm -f
TARGET_LIB = build/liblwip.so

SRCS = lwip/src/api/err.c \
	lwip/src/core/def.c \
	lwip/src/core/init.c \
	lwip/src/core/mem.c \
	lwip/src/core/memp.c \
	lwip/src/core/netif.c \
	lwip/src/core/pbuf.c \
	lwip/src/core/raw.c \
	lwip/src/core/ipv4/icmp.c \
	lwip/src/core/inet_chksum.c \
	lwip/src/core/ip.c \
	lwip/src/core/ipv4/ip4_addr.c \
	lwip/src/core/ipv4/ip4_frag.c \
	lwip/src/core/timeouts.c \
	lwip/src/core/udp.c \
	lwip/src/core/tcp.c \
	lwip/src/core/tcp_out.c \
	lwip/src/core/tcp_in.c \
	lwip/src/core/ipv4/etharp.c \
	lwip/src/netif/ethernet.c \
	lwip/src/core/ipv4/ip4.c \
	lwip-contrib/ports/unix/port/sys_arch.c

INCLUDES = -I$(ROOT_DIR)\
	-I$(ROOT_DIR)/lwip-contrib/ports/unix/port/include/ \
	-I$(ROOT_DIR)/lwip/src/include/ipv4 \
	-I$(ROOT_DIR)/lwip/src/include

CFLAGS += $(INCLUDES)

OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	mkdir -p build
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)