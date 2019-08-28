/*
 * Check decoding of clone3 syscall.
 *
 * Copyright (c) 2019 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tests.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef HAVE_LINUX_SCHED_H
# include <linux/sched.h>
#endif

#ifdef HAVE_STRUCT_USER_DESC
# include <asm/ldt.h>
#endif

#include "scno.h"

#ifndef VERBOSE
# define VERBOSE 0
#endif
#ifndef INJECTED
# define INJECTED 0
#endif


#ifndef HAVE_STRUCT_CLONE_ARGS
# include <stdint.h>
# include <linux/types.h>

# define XLAT_MACROS_ONLY
#  include "xlat/clone_flags.h"
# undef XLAT_MACROS_ONLY

struct clone_args {
	__u64 flags;
	__u64 pidfd;
	__u64 child_tid;
	__u64 parent_tid;
	__u64 exit_signal;
	__u64 stack;
	__u64 stack_size;
	__u64 tls;
};
#endif /* !HAVE_STRUCT_CLONE_ARGS */

enum validity_flag_bits {
	STRUCT_VALID_BIT,
	PIDFD_VALID_BIT,
	CHILD_TID_VALID_BIT,
	PARENT_TID_VALID_BIT,
	TLS_VALID_BIT,
};

#define _(x_) x_ = 1 << x_##_BIT

enum validity_flags {
	_(STRUCT_VALID),
	_(PIDFD_VALID),
	_(CHILD_TID_VALID),
	_(PARENT_TID_VALID),
	_(TLS_VALID),
};

#undef _

static const int child_exit_status = 42;


static void
wait_cloned(int pid)
{
	int status;

	errno = 0;
	while (waitpid(pid, &status, WEXITED | __WCLONE) != pid) {
		if (errno != EINTR)
			perror_msg_and_fail("waitpid(%d)", pid);
	}
}

static long
do_clone3_(void *args, kernel_ulong_t size, bool should_fail, int line)
{
	long rc = syscall(__NR_clone3, args, size);

	if (should_fail && rc >= 0)
		error_msg_and_fail("%d: Unexpected success of a clone3() call",
				   line);

	if (!should_fail && rc < 0 && errno != ENOSYS)
		perror_msg_and_fail("%d: Unexpected failure of a clone3() call",
				    line);

	if (!rc)
		_exit(child_exit_status);

	if (rc > 0 && ((struct clone_args *) args)->exit_signal)
		wait_cloned(rc);

	return rc;
}

#define do_clone3(args_, size_, should_fail_) \
	do_clone3_((args_), (size_), (should_fail_), __LINE__)

static inline void
print_addr64(const char *pfx, uint64_t addr)
{
	if (addr)
		printf("%s%#" PRIx64, pfx, addr);
	else
		printf("%sNULL", pfx);
}

static void
print_tls(const char *pfx, uint64_t arg_ptr, enum validity_flags vf)
{
# ifdef HAVE_STRUCT_USER_DESC
	if (!(vf & TLS_VALID)) {
		print_addr64(pfx, arg_ptr);
		return;
	}

	struct user_desc *arg = (struct user_desc *) (uintptr_t) arg_ptr;

	printf("%s{entry_number=%d"
	       ", base_addr=%#08x"
	       ", limit=%#08x"
	       ", seg_32bit=%u"
	       ", contents=%u"
	       ", read_exec_only=%u"
	       ", limit_in_pages=%u"
	       ", seg_not_present=%u"
	       ", useable=%u}",
	       pfx,
	       arg->entry_number,
	       arg->base_addr,
	       arg->limit,
	       arg->seg_32bit,
	       arg->contents,
	       arg->read_exec_only,
	       arg->limit_in_pages,
	       arg->seg_not_present,
	       arg->useable);
# else
	print_addr64(pfx, arg_ptr);
# endif
}

static inline void
print_clone3(struct clone_args *const arg, long rc, kernel_ulong_t sz,
	     enum validity_flags valid,
	     const char *flags_str, const char *es_str)
{
	int saved_errno = errno;

	if (!(valid & STRUCT_VALID)) {
		printf("%p", arg);
		goto out;
	}

	printf("{flags=%s", flags_str);

	if (arg->flags & CLONE_PIDFD)
		print_addr64(", pidfd=", arg->pidfd);

	if (arg->flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) {
		if (valid & CHILD_TID_VALID)
			printf(", child_tid=[%d]",
			       *(int *) (uintptr_t) arg->child_tid);
		else
			print_addr64(", child_tid=", arg->child_tid);
	}

	if (arg->flags & CLONE_PARENT_SETTID)
		print_addr64(", parent_tid=", arg->parent_tid);

	printf(", exit_signal=%s", es_str);
	print_addr64(", stack=", arg->stack);
	printf(", stack_size=%" PRIx64, (uint64_t) arg->stack_size);

	if (arg->flags & CLONE_SETTLS)
		print_tls("tls=", arg->tls, valid);

	printf("}");

	if (rc < 0)
		goto out;

	bool comma = false;

	if (arg->flags & CLONE_PIDFD) {
		if (valid & PIDFD_VALID)
			printf(" => {pidfd=[%d]",
			       *(int *) (uintptr_t) arg->pidfd);
		else
			print_addr64(" => {pidfd=", arg->pidfd);

		comma = true;
	}

	if (arg->flags & CLONE_PARENT_SETTID) {
		printf(comma ? ", " : " => {");

		if (valid & PARENT_TID_VALID)
			printf("parent_tid=[%d]",
			       *(int *) (uintptr_t) arg->parent_tid);
		else
			print_addr64("parent_tid=", arg->parent_tid);

		comma = true;
	}

out:
	errno = saved_errno;
}

int
main(int argc, char *argv[])
{
	static const struct {
		struct clone_args args;
		bool should_fail;
		enum validity_flags vf;
		const char *flags_str;
		const char *es_str;
	} arg_vals[] = {
		{ { .flags = 0 },
			false, 0, "0", "0" },
	};

	struct clone_args *arg = tail_alloc(sizeof(*arg));
	struct clone_args *arg2 = tail_alloc(sizeof(*arg2) + 8);
	int *pidfd = tail_alloc(sizeof(*pidfd));
	int *child_tid = tail_alloc(sizeof(*child_tid));
	int *parent_tid = tail_alloc(sizeof(*parent_tid));
	long rc;

# ifdef HAVE_STRUCT_USER_DESC
	struct user_desc *tls = tail_alloc(sizeof(*tls));

	fill_memory(tls, sizeof(*tls));
# endif

	*pidfd = 0xbadc0ded;
	*child_tid = 0xdeadface;
	*parent_tid = 0xfeedbeef;

	rc = do_clone3(NULL, 0, true);
	printf("clone3(NULL, 0) = %s\n", sprintrc(rc));

	rc = do_clone3(arg + 1, sizeof(*arg), true);
	printf("clone3(%p, %zu) = %s\n",
	       arg + 1, sizeof(*arg), sprintrc(rc));

	rc = do_clone3((char *) arg + sizeof(uint64_t),
		       sizeof(*arg) - sizeof(uint64_t), true);
	printf("clone3(%p, %zu) = %s\n",
	       (char *) arg + sizeof(uint64_t), sizeof(*arg) - sizeof(uint64_t),
	       sprintrc(rc));


	memset(arg, 0, sizeof(*arg));
	memset(arg2, 0, sizeof(*arg2) + 8);

	rc = do_clone3(arg, 64, false);
	printf("clone3({flags=0, exit_signal=0, stack=NULL, stack_size=0}, 64)"
	       " = %s\n",
	       sprintrc(rc));

	rc = do_clone3(arg, sizeof(*arg) + 8, true);
	printf("clone3({flags=0, exit_signal=0, stack=NULL, stack_size=0, ...}"
	       ", %zu) = %s\n",
	       sizeof(*arg) + 8, sprintrc(rc));

	rc = do_clone3(arg2, sizeof(*arg2) + 8, false);
	printf("clone3({flags=0, exit_signal=0, stack=NULL, stack_size=0}"
	       ", %zu) = %s\n",
	       sizeof(*arg2) + 8, sprintrc(rc));

	arg2[1].flags = 0xfacefeeddeadc0de;
	rc = do_clone3(arg2, sizeof(*arg2) + 8, true);
	printf("clone3({flags=0, exit_signal=0, stack=NULL, stack_size=0"
	       ", /* bytes %zu..%zu */ "
#if WORDS_BIGENDIAN
	       "\"\\xfa\\xce\\xfe\\xed\\xde\\xad\\xc0\\xde\""
#else
	       "\"\\xde\\xc0\\xad\\xde\\xed\\xfe\\xce\\xfa\""
#endif
	       "}, %zu) = %s\n",
	       sizeof(*arg2), sizeof(*arg2) + 7,
	       sizeof(*arg2) + 8, sprintrc(rc));

	arg->flags = 0xfacefeedbeefc0de;
	rc = do_clone3(arg2, sizeof(*arg) + 16, true);
	printf("clone3({flags=0, exit_signal=0, stack=NULL, stack_size=0, ...}"
	       ", %zu) = %s\n",
	       sizeof(*arg) + 16, sprintrc(rc));

	arg->flags = 0xfacefeedbeefc0de;
	rc = do_clone3(arg, 64, true);
	printf("clone3({flags=CLONE_VFORK|CLONE_PARENT|CLONE_THREAD|CLONE_NEWNS"
	       "|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_CHILD_CLEARTID|CLONE_UNTRACED"
	       "|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER"
	       "|CLONE_NEWPID|CLONE_IO|0xfacefeed004000de, child_tid=NULL"
	       ", exit_signal=0, stack=NULL, stack_size=0, tls=NULL}, 64)"
	       " = %s\n", sprintrc(rc));

	arg->flags = 0xdec0dead004000ffULL;
	arg->exit_signal = 0xdeadfacebadc0dedULL; /* it is int in kernel */
	arg->stack = 0xface1e55beeff00dULL;
	arg->stack_size = 0xcaffeedefacedca7ULL;
	rc = do_clone3(arg, 64, true);
	printf("clone3({flags=0xdec0dead004000ff /* CLONE_??? */"
	       ", exit_signal=-1159983635, stack=0xface1e55beeff00d"
	       ", stack_size=0xcaffeedefacedca7}, 64) = %s\n", sprintrc(rc));

	arg->exit_signal = 0xdeadface00000009ULL; /* SIGKILL */

	struct {
		__u64 flag;
		const char *flag_str;
		__u64 *field;
		const char *field_name;
		int *ptr;
		bool deref_exiting;
	} pid_fields[] = {
		{ ARG_STR(CLONE_PIDFD),
			&arg->pidfd, "pidfd", pidfd },
		{ ARG_STR(CLONE_CHILD_SETTID),
			&arg->child_tid, "child_tid", child_tid },
		{ ARG_STR(CLONE_CHILD_CLEARTID),
			&arg->child_tid, "child_tid", child_tid },
		{ ARG_STR(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID),
			&arg->child_tid, "child_tid", child_tid },
		{ ARG_STR(CLONE_PARENT_SETTID),
			&arg->parent_tid, "parent_tid", parent_tid },
	};

	for (size_t i = 0; i < ARRAY_SIZE(pid_fields); i++) {
		arg->flags = 0xbad0000000000001ULL | pid_fields[i].flag;
		pid_fields[i].field[0] = 0;
		rc = do_clone3(arg, 64, true);
		printf("clone3({flags=%s|0xbad0000000000001, %s=NULL"
		       ", exit_signal=SIGKILL, stack=0xface1e55beeff00d"
		       ", stack_size=0xcaffeedefacedca7}, 64) = %s\n",
		       pid_fields[i].flag_str, pid_fields[i].field_name,
		       sprintrc(rc));

		pid_fields[i].field[0] = (uintptr_t) (pid_fields[i].ptr + 1);
		rc = do_clone3(arg, 64, true);
		printf("clone3({flags=%s|0xbad0000000000001, %s=%p"
		       ", exit_signal=SIGKILL, stack=0xface1e55beeff00d"
		       ", stack_size=0xcaffeedefacedca7}, 64) = %s\n",
		       pid_fields[i].flag_str, pid_fields[i].field_name,
		       pid_fields[i].ptr + 1, sprintrc(rc));

		pid_fields[i].field[0] = (uintptr_t) pid_fields[i].ptr;
		rc = do_clone3(arg, 64, true);
		printf("clone3({flags=%s|0xbad0000000000001, %s=%p"
		       ", exit_signal=SIGKILL, stack=0xface1e55beeff00d"
		       ", stack_size=0xcaffeedefacedca7}, 64) = %s\n",
		       pid_fields[i].flag_str, pid_fields[i].field_name,
		       pid_fields[i].ptr, sprintrc(rc));
	}

	for (size_t i = 0; i < ARRAY_SIZE(arg_vals); i++) {
		memcpy(arg, &arg_vals[i].args, sizeof(*arg));

		rc = do_clone3(arg, sizeof(*arg), arg_vals[i].should_fail);
		printf("clone3(");
		print_clone3(arg, rc, sizeof(*arg),
			     arg_vals[i].vf | STRUCT_VALID,
			     arg_vals[i].flags_str, arg_vals[i].es_str);
		printf(", %zu) = %s\n", sizeof(*arg), sprintrc(rc));
	}

	puts("+++ exited with 0 +++");

	return 0;
}
