/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "pb/rootlesscontainers.pb-c.h"
#include <errno.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

/*
 * recvfd() was copied from
 * https://github.com/rootless-containers/slirp4netns/blob/d5c44a94a271701ddc48c9b20aa6e9539a92ad0a/main.c#L110-L141
 * The author (Akihiro Suda) relicensed the code to LGPL v2.1.
 */
static int recvfd(int sock) {
  int fd;
  ssize_t rc;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  char cmsgbuf[CMSG_SPACE(sizeof(fd))];
  struct iovec iov;
  char dummy = '\0';
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = &dummy;
  iov.iov_len = 1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  if ((rc = recvmsg(sock, &msg, 0)) < 0) {
    perror("recvmsg");
    return (int)rc;
  }
  if (rc == 0) {
    fprintf(stderr, "the message is empty\n");
    return -1;
  }
  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
    fprintf(stderr, "the message does not contain fd\n");
    return -1;
  }
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  return fd;
}

static int read_proc_mem_string(char **out, pid_t pid, off_t off,
                                size_t max_len) {
  const size_t buf_len = max_len + 1;
  char *buf = malloc(buf_len);
  struct iovec local[1];
  struct iovec remote[1];
  ssize_t nread;
  local[0].iov_base = buf;
  local[0].iov_len = buf_len;
  remote[0].iov_base = (void *)off;
  remote[0].iov_len = buf_len;
  if ((nread = process_vm_readv(pid, local, 1, remote, 1, 0)) < 0) {
    perror("process_vm_readv");
    free(buf);
    *out = NULL;
    return nread;
  }
  buf[max_len] = '\0';
  *out = buf;
  return 0;
}

#define USER_ROOTLESSCONTAINERS_XATTR "user.rootlesscontainers"

static int set_user_rootlesscontainers_xattr_chdired(const char *pathname,
                                                     uid_t uid, gid_t gid) {
  uint8_t *buf = NULL;
  size_t sz = 0;
  int rc = -1;
  Rootlesscontainers__Resource msg;
  if (uid == 0 && gid == 0) {
    printf("DEBUG: removing %s xattr on \"%s\" in the PID cwd\n",
           USER_ROOTLESSCONTAINERS_XATTR, pathname);
    if ((rc = removexattr(pathname, USER_ROOTLESSCONTAINERS_XATTR)) < 0) {
      perror("removexattr");
    }
    return rc;
  }
  rootlesscontainers__resource__init(&msg);
  msg.uid = uid;
  msg.gid = gid;
  sz = rootlesscontainers__resource__get_packed_size(&msg);
  buf = malloc(sz);
  rootlesscontainers__resource__pack(&msg, buf);
  printf("DEBUG: setting %s xattr (%ld bytes) on \"%s\" in the PID cwd\n",
         USER_ROOTLESSCONTAINERS_XATTR, sz, pathname);
  if ((rc = setxattr(pathname, USER_ROOTLESSCONTAINERS_XATTR, buf, sz, 0)) <
      0) {
    perror("setxattr");
  }
  free(buf);
  return rc;
}

static int set_user_rootlesscontainers_xattr(pid_t pid, const char *pathname,
                                             uid_t uid, gid_t gid) {
  char proc_pid_cwd[32];
  char *wd = NULL;
  int rc = -1;
  sprintf(proc_pid_cwd, "/proc/%d/cwd", pid);
  if ((wd = get_current_dir_name()) == NULL) {
    perror("get_current_dir_name");
    return -1;
  }
  if ((rc = chdir(proc_pid_cwd)) < 0) {
    perror("chdir");
    free(wd);
    return rc;
  }
  rc = set_user_rootlesscontainers_xattr_chdired(pathname, uid, gid);
  if (chdir(wd) < 0) {
    perror("chdir");
    fprintf(stderr, "can't chdir back to the previous wd \"%s\", aborting\n",
            wd);
    free(wd);
    abort();
    return -1;
  }
  free(wd);
  return 0;
}

static void handle_sys_chown(struct seccomp_notif *req,
                             struct seccomp_notif_resp *resp) {
  char *pathname = NULL;
  uid_t uid = req->data.args[1];
  gid_t gid = req->data.args[2];
  read_proc_mem_string(&pathname, req->pid, req->data.args[0], PATH_MAX);
  fprintf(stderr, "debug: <<< ID=%llud sys_chown(\"%s\", %d, %d)\n", req->id,
          pathname, uid, gid);
  if (set_user_rootlesscontainers_xattr(req->pid, pathname, uid, gid) < 0) {
    resp->error = -1;
    resp->error = -EIO;
  }
  fprintf(stderr, "debug: >>> ID=%llud error=%d\n", req->id, resp->error);
  free(pathname);
}

static void handle_req(struct seccomp_notif *req,
                       struct seccomp_notif_resp *resp) {
  resp->id = req->id;
  switch (req->data.nr) {
  /* FIXME: use SCMP_SYS macro */
  case __NR_chown:
    handle_sys_chown(req, resp);
    break;
  default:
    fprintf(stderr, "Unexpected syscall %d, returning -ENOTSUP\n",
            req->data.nr);
    resp->error = -ENOTSUP;
    break;
  }
}

static int on_accept(int accept_fd) {
  int notify_fd = -1;
  if ((notify_fd = recvfd(accept_fd)) < 0) {
    perror("recvfd");
    return notify_fd;
  }
  printf("received notify_fd=%d\n", notify_fd);
  for (;;) {
    int rc = -1;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if ((rc = seccomp_notify_alloc(&req, &resp)) < 0) {
      fprintf(stderr, "seccomp_notify_alloc() failed, rc=%d\n", rc);
      return rc;
    }
    if ((rc = seccomp_notify_receive(notify_fd, req)) < 0) {
      fprintf(stderr, "seccomp_notify_receive() failed, rc=%d\n", rc);
      seccomp_notify_free(req, resp);
      return rc;
    }
    if ((rc = seccomp_notify_id_valid(notify_fd, req->id)) < 0) {
      fprintf(stderr, "req->id=%lld is no longer valid, ignoring\n", req->id);
      seccomp_notify_free(req, resp);
      continue;
    }
    handle_req(req, resp);
    if ((rc = seccomp_notify_respond(notify_fd, resp)) < 0) {
      fprintf(stderr, "seccomp_notify_respond() failed, rc=%d\n", rc);
      seccomp_notify_free(req, resp);
      return rc;
    }
    seccomp_notify_free(req, resp);
  }
}

int main(int argc, char *const argv[]) {
  const char *sock_path = NULL;
  int sock_fd = -1;
  const int sock_backlog = 128;
  struct sockaddr_un sun;
  if (argc != 2) {
    fprintf(stderr, "Usage: %s SOCK\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  sock_path = argv[1];
  unlink(sock_path); /* remove existing socket */
  if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  memset(&sun, 0, sizeof(struct sockaddr_un));
  sun.sun_family = AF_UNIX;
  strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
  if (bind(sock_fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
    perror("bind");
    exit(EXIT_FAILURE);
  }
  if (listen(sock_fd, sock_backlog) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  printf("Listening on %s\n", sock_path);
  for (int i = 0;; i++) {
    int accept_fd = -1;
    if ((accept_fd = accept(sock_fd, NULL, NULL)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }
    if (i > 1) {
      fprintf(stderr, "FIXME: only single accept() is supported currently\n");
      close(accept_fd);
      continue;
    }
    /* TODO: fork() here */
    if (!on_accept(accept_fd)) {
      fprintf(stderr, "on_accept() failed\n");
      exit(EXIT_FAILURE);
    }
    close(accept_fd);
  }
  exit(EXIT_SUCCESS);
}
