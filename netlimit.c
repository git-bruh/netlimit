#define _GNU_SOURCE
#include <errno.h>
#include <linux/if.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// ip link add name <SOCKET_INTERFACE> link <LIVE_INTERFACE> type ipvlan mode l2
// tc qdisc add dev <SOCKET_INTERFACE> root netem <...>

_Noreturn static void
panic(const char *const func) {
	perror(func);
	abort();
}

static void
sendfd(int sockFd, int fd) {
	// TODO dedup
	// Union for alignment
	union {
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} cmsgu = {0};

	struct iovec iov = {.iov_base = &(char) {'\0'}, .iov_len = 1};

	// msg_{{name,iov}len,flags} zeroed
	struct msghdr msg = {
	  .msg_iov = &iov,
	  .msg_iovlen = 1,
	  .msg_control = cmsgu.buf,
	  .msg_controllen = sizeof(cmsgu.buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	if (sendmsg(sockFd, &msg, 0) == -1) {
		panic("sendmsg");
	}
}

static int
recvfd(int sockFd) {
	int fd = -1;

	// Union for alignment
	union {
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} cmsgu = {0};

	struct iovec iov = {.iov_base = &(char) {'\0'}, .iov_len = 1};

	// msg_{{name,iov}len,flags} zeroed
	struct msghdr msg = {
	  .msg_iov = &iov,
	  .msg_iovlen = 1,
	  .msg_control = cmsgu.buf,
	  .msg_controllen = sizeof(cmsgu.buf),
	};

	if (recvmsg(sockFd, &msg, 0) == -1) {
		panic("recvmsg");
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

	return fd;
}

static pid_t
tracedProcess(int sockFd, const char *file, char *const argv[]) {
	pid_t pid = fork();

	if (pid == -1) {
		panic("fork");
	}
	if (pid != 0) {
		return pid;
	}

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

	if (!ctx) {
		panic("seccomp_init");
	}

	if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(socket), 0) == -1) {
		panic("seccomp_rule_add");
	}

	if (seccomp_load(ctx) == -1) {
		panic("seccomp_load");
	}

	int fd = seccomp_notify_fd(ctx);

	if (fd == -1) {
		panic("seccomp_notify_fd");
	}

	sendfd(sockFd, fd);

	close(fd);
	close(sockFd);

	seccomp_release(ctx);

	if (execvp(file, argv) == -1) {
		panic("execvp");
	}

	__builtin_unreachable();
}

int
main(int argc, char *const argv[]) {
	if (argc < 3) {
		return EXIT_FAILURE;
	}

	struct ifreq ifreq = {0};
	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", argv[1]);

	int sockPair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1) {
		panic("socketpair");
	}

	// TODO monitor
	tracedProcess(sockPair[0], argv[2], &argv[2]);

	int fd = recvfd(sockPair[1]);

	close(sockPair[0]);
	close(sockPair[1]);

	struct seccomp_notif *req = NULL;
	struct seccomp_notif_resp *resp = NULL;

	if (seccomp_notify_alloc(&req, &resp) == -1) {
		panic("seccomp_notify_alloc");
	}

	while (true) {
		memset(req, 0, sizeof(*req));

		if (seccomp_notify_receive(fd, req) < 0) {
			panic("seccomp_notify_receive");
		}

		int domain = req->data.args[0], type = req->data.args[1],
			protocol = req->data.args[2];
		int socket = syscall(__NR_socket, domain, type, protocol);

		if (socket == -1) {
			resp->id = req->id;
			resp->val = 0;
			resp->error = -errno;
			resp->flags = req->flags;

			if (seccomp_notify_respond(fd, resp) < 0) {
				panic("seccomp_notify_respond");
			}

			continue;
		}

		if ((domain & AF_INET) || (domain & AF_INET6)) {
			if (setsockopt(
				  socket, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq))
				== -1) {
				perror("setsockopt");
			}
		}

		if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD,
			  &(struct seccomp_notif_addfd) {
				.id = req->id,
				.flags = SECCOMP_ADDFD_FLAG_SEND,
				.srcfd = socket,
			  })
			< 0) {
			panic("ioctl(SECCOMP_IOCTL_NOTIF_ADDFD)");
		}

		close(socket);
	}

	close(fd);
	seccomp_notify_free(req, resp);
}
