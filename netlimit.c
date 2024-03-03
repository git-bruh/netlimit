#define _GNU_SOURCE

#include <dlfcn.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

// ip link add name <SOCKET_INTERFACE> link <LIVE_INTERFACE> type ipvlan mode l2
// tc qdisc add dev <SOCKET_INTERFACE> root netem <...>

static void *handle = NULL;
static struct ifreq interface = {0};
static int (*real_socket)(int, int, int) = NULL;

__attribute__((constructor)) static void init(void) {
  if (!(handle = dlopen("libc.so.6", RTLD_LAZY))) {
    perror("dlopen");
    abort();
  }

  if (!(real_socket = dlsym(handle, "socket"))) {
    perror("dlsym");
    abort();
  }

  char *interface_str = getenv("SOCKET_INTERFACE");

  if (!interface_str) {
    fputs("No interface specified in SOCKET_INTERFACE\n", stderr);
    abort();
  }

  snprintf(interface.ifr_name, sizeof(interface.ifr_name), "%s", interface_str);
}

int socket(int domain, int type, int protocol) {
  int fd = real_socket(domain, type, protocol);

  if ((domain & AF_INET) || (domain & AF_INET6)) {
    // https://github.com/Gnurou/busybox/blob/d9e0c438e10e2155513e5d26498af472c5137d65/libbb/xconnect.c#L27
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                   sizeof(interface)) != 0) {
      perror("setsockopt");
      abort();
    }
  }

  return fd;
}

__attribute__((destructor)) static void finish(void) { dlclose(handle); }
