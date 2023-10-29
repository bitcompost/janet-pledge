/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "landlock.h"
/*
#include "libc/intrin/strace.internal.h"

int sys_landlock_add_rule(int, enum landlock_rule_type, const void *, uint32_t);
*/

#include <sys/syscall.h>
#include <unistd.h>

/**
 * Adds new rule to Landlock ruleset.
 *
 * @error ENOSYS if Landlock isn't supported
 * @error EPERM if Landlock supported but SECCOMP BPF shut it down
 * @error EOPNOTSUPP if Landlock supported but disabled at boot time
 * @error EINVAL if flags not 0, or inconsistent access in the rule,
 *     i.e. landlock_path_beneath_attr::allowed_access is not a subset
 *     of the ruleset handled accesses
 * @error ENOMSG empty allowed_access
 * @error EBADF `fd` is not a file descriptor for current thread, or
 *     member of `rule_attr` is not a file descriptor as expected
 * @error EBADFD `fd` is not a ruleset file descriptor, or a member
 *     of `rule_attr` is not the expected file descriptor type
 * @error EPERM `fd` has no write access to the underlying ruleset
 * @error EFAULT `rule_attr` inconsistency
 */
int landlock_add_rule(int fd, enum landlock_rule_type rule_type,
                      const void *rule_attr, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_add_rule, fd, rule_type, rule_attr, flags);
  /*KERNTRACE("landlock_add_rule(%d, %d, %p, %#x) → %d% m", fd, rule_type,
            rule_attr, flags, rc);*/
  return rc;
}
/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
/**
 * Create new Landlock filesystem sandboxing ruleset.
 *
 * You may also use this function to query the current ABI version:
 *
 *     landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION);
 *
 * @return close exec file descriptor for new ruleset
 * @error ENOSYS if not running Linux 5.13+
 * @error EPERM if pledge() or seccomp bpf shut it down
 * @error EOPNOTSUPP Landlock supported but disabled at boot
 * @error EINVAL unknown flags, or unknown access, or too small size
 * @error E2BIG attr or size inconsistencies
 * @error EFAULT attr or size inconsistencies
 * @error ENOMSG empty landlock_ruleset_attr::handled_access_fs
 */
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                            size_t size, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_create_ruleset, attr, size, flags);
  //KERNTRACE("landlock_create_ruleset(%p, %'zu, %#x) → %d% m", attr, size, flags,
  //          rc);
  return rc;
}
/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
/**
 * Enforces Landlock ruleset on calling thread.
 *
 * @error EOPNOTSUPP if Landlock supported but disabled at boot time
 * @error EINVAL if flags isn't zero
 * @error EBADF if `fd` isn't file descriptor for the current thread
 * @error EBADFD if `fd` is not a ruleset file descriptor
 * @error EPERM if `fd` has no read access to underlying ruleset, or
 *     current thread is not running with no_new_privs, or it doesn’t
 *     have CAP_SYS_ADMIN in its namespace
 * @error E2BIG if the maximum number of stacked rulesets is
 *     reached for current thread
 */
int landlock_restrict_self(int fd, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_restrict_self, fd, flags);
  //KERNTRACE("landlock_create_ruleset(%d, %#x) → %d% m", fd, flags, rc);
  return rc;
}
