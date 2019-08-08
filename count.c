/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *                     Linux for s390 port by D.J. Barrow
 *                    <barrow_dj@mail.yahoo.com,djbarrow@de.ibm.com>
 * Copyright (c) 2004 Roland McGrath <roland@redhat.com>
 * Copyright (c) 2006 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2006-2018 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

#include <stdarg.h>

/* Per-syscall stats structure */
struct call_counts {
	/* time may be total latency or system time */
	struct timespec time;
	double time_avg;
	uint64_t calls, errors;
};

static struct call_counts *countv[SUPPORTED_PERSONALITIES];
#define counts (countv[current_personality])

static const struct timespec zero_ts;

static struct timespec overhead;


enum count_summary_columns {
	CSC_NONE,
	CSC_TIME_100S,
	CSC_TIME_TOTAL,
	CSC_TIME_AVG,
	CSC_CALLS,
	CSC_ERRORS,
	CSC_SC_NAME,

	CSC_MAX,
};

static uint8_t columns[CSC_MAX] = {
	CSC_TIME_100S,
	CSC_TIME_TOTAL,
	CSC_TIME_AVG,
	CSC_CALLS,
	CSC_ERRORS,
	CSC_SC_NAME,
};

void
count_syscall(struct tcb *tcp, const struct timespec *syscall_exiting_ts)
{
	if (!scno_in_range(tcp->scno))
		return;

	if (!counts)
		counts = xcalloc(nsyscalls, sizeof(*counts));
	struct call_counts *cc = &counts[tcp->scno];

	cc->calls++;
	if (syserror(tcp))
		cc->errors++;

	struct timespec wts;
	if (count_wallclock) {
		/* wall clock time spent while in syscall */
		ts_sub(&wts, syscall_exiting_ts, &tcp->etime);
	} else {
		/* system CPU time spent while in syscall */
		ts_sub(&wts, &tcp->stime, &tcp->ltime);
	}

	ts_sub(&wts, &wts, &overhead);
	ts_add(&cc->time, &cc->time, ts_max(&wts, &zero_ts));
}

static int
time_cmp(const void *a, const void *b)
{
	const unsigned int *a_int = a;
	const unsigned int *b_int = b;
	return -ts_cmp(&counts[*a_int].time, &counts[*b_int].time);
}

static int
syscall_cmp(const void *a, const void *b)
{
	const unsigned int *a_int = a;
	const unsigned int *b_int = b;
	const char *a_name = sysent[*a_int].sys_name;
	const char *b_name = sysent[*b_int].sys_name;
	return strcmp(a_name ? a_name : "", b_name ? b_name : "");
}

static int
count_cmp(const void *a, const void *b)
{
	const unsigned int *a_int = a;
	const unsigned int *b_int = b;
	unsigned int m = counts[*a_int].calls;
	unsigned int n = counts[*b_int].calls;

	return (m < n) ? 1 : (m > n) ? -1 : 0;
}

static int
error_cmp(const void *a, const void *b)
{
	const unsigned int *a_int = a;
	const unsigned int *b_int = b;
	unsigned int m = counts[*a_int].errors;
	unsigned int n = counts[*b_int].errors;

	return (m < n) ? 1 : (m > n) ? -1 : 0;
}

static int (*sortfun)(const void *, const void *);

void
set_sortby(const char *sortby)
{
	static const struct {
		int (*fn)(const void *, const void *);
		const char *name;
	} sort_fns[] = {
		{ time_cmp,	"time" },
		{ time_cmp,	"time_total" },
		{ time_cmp,	"total_time" },
		{ count_cmp,	"calls" },
		{ count_cmp,	"count" },
		{ error_cmp,	"error" },
		{ error_cmp,	"errors" },
		{ syscall_cmp,	"name" },
		{ syscall_cmp,	"syscall" },
		{ syscall_cmp,	"syscall_name" },
		{ NULL,		"none" },
		{ NULL,		"nothing" },
	};

	for (size_t i = 0; i < ARRAY_SIZE(sort_fns); ++i) {
		if (!strcmp(sort_fns[i].name, sortby)) {
			sortfun = sort_fns[i].fn;
			return;
		}
	}

	error_msg_and_help("invalid sortby: '%s'", sortby);
}

int
set_overhead(const char *str)
{
	return parse_ts(str, &overhead);
}

static size_t ATTRIBUTE_FORMAT((printf, 1, 2))
num_chars(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int ret = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	return (unsigned int) MAX(ret, 0);
}

static void
call_summary_pers(FILE *outf)
{
	enum column_flags {
		CF_L = 1 << 0, /* Left-aligned column */
	};
	static const struct {
		const char *s;
		size_t sz;
		const char *fmt;
		const char *last_fmt;
		uint32_t flags;
	} cdesc[] = {
		[CSC_TIME_100S]  = { ARRSZ_PAIR("% time"),     "%*.2f" },
		[CSC_TIME_TOTAL] = { ARRSZ_PAIR("seconds"),    "%*.6f" },
		[CSC_TIME_AVG]   = { ARRSZ_PAIR("usecs/call"), "%*" PRIu64 },
		[CSC_CALLS]      = { ARRSZ_PAIR("calls"),      "%*" PRIu64 },
		[CSC_ERRORS]     = { ARRSZ_PAIR("errors"),     "%*" PRIu64 },
		[CSC_SC_NAME]    = { ARRSZ_PAIR("syscall"),
				     "%-*s", "%2$s", CF_L },
	};

	unsigned int *indices;
	size_t last_column = 0;

	struct timespec tv_cum = zero_ts;
	uint64_t call_cum = 0;
	uint64_t error_cum = 0;

	double float_tv_cum;
	double percent;

	double ts_avg_max = 0;
	size_t sc_name_max = 0;


	/* sort, calculate statistics */
	indices = xcalloc(sizeof(indices[0]), nsyscalls);
	for (size_t i = 0; i < nsyscalls; i++) {
		struct timespec dtv;

		indices[i] = i;
		if (counts[i].calls == 0)
			continue;

		ts_add(&tv_cum, &tv_cum, &counts[i].time);
		call_cum += counts[i].calls;
		error_cum += counts[i].errors;

		ts_div(&dtv, &counts[i].time, counts[i].calls);
		counts[i].time_avg = ts_float(&dtv);

		ts_avg_max = MAX(ts_avg_max, counts[i].time_avg);
		sc_name_max = MAX(sc_name_max, strlen(sysent[i].sys_name));
	}
	float_tv_cum = ts_float(&tv_cum);

	if (sortfun)
		qsort((void *) indices, nsyscalls, sizeof(indices[0]), sortfun);

	/* calculate column widths */
#define W_(c_, v_) [c_] = MAX((cdesc[c_].sz - 1), (v_))
	unsigned int cwidths[CSC_MAX] = {
		W_(CSC_TIME_100S,  sizeof("100.00") - 1),
		W_(CSC_TIME_TOTAL, num_chars("%.6f", float_tv_cum)),
		W_(CSC_TIME_AVG,   num_chars("%" PRIu64,
					     (uint64_t) (ts_avg_max * 1e6))),
		W_(CSC_CALLS,      num_chars("%" PRIu64, call_cum)),
		W_(CSC_ERRORS,     num_chars("%" PRIu64, error_cum)),
		W_(CSC_SC_NAME,    sc_name_max + 1),
	};
#undef W_

	/* find the last column */
	for (size_t i = 0; columns[i] && i < ARRAY_SIZE(columns); i++)
		last_column = i;

	/* header */
	for (size_t i = 0; i <= last_column; i++) {
		const char *fmt = cdesc[columns[i]].flags & CF_L
				  ? (i == last_column ? "%2$s" : "%-*s")
				  : "%*s";
		if (i)
			fputc(' ', outf);
		fprintf(outf, fmt, cwidths[columns[i]], cdesc[columns[i]].s);
	}
	fputc('\n', outf);

	/* divider */
	for (size_t i = 0; i <= last_column; i++) {
		if (i)
			fputc(' ', outf);

		for (size_t j = 0; j < cwidths[columns[i]]; j++)
			fputc('-', outf);
	}
	fputc('\n', outf);

	/* data output */
	for (size_t j = 0; j < nsyscalls; j++) {
		unsigned int idx = indices[j];
		struct call_counts *cc = &counts[idx];
		double float_syscall_time;

		if (cc->calls == 0)
			continue;

		float_syscall_time = ts_float(&cc->time);
		percent = (100.0 * float_syscall_time);
		/* else: float_tv_cum can be 0.0 too and we get 0/0 = NAN */
		if (percent != 0.0)
			   percent /= float_tv_cum;

		for (size_t i = 0; i <= last_column; i++) {
			const size_t c = columns[i];
			if (i)
				fputc(' ', outf);

#define PC_(c_, val_) \
	case (c_): \
		fprintf(outf, \
			(i == last_column) && cdesc[c].last_fmt \
				? cdesc[c].last_fmt : cdesc[c].fmt, \
			cwidths[c], (val_)); \
		break;

			switch (c) {
			PC_(CSC_TIME_100S,  percent)
			PC_(CSC_TIME_TOTAL, float_syscall_time)
			PC_(CSC_TIME_AVG,   (uint64_t) (cc->time_avg * 1e6))
			PC_(CSC_CALLS,      cc->calls)
			case CSC_ERRORS:
				if (cc->errors)
					fprintf(outf, cdesc[c].fmt,
						cwidths[c], cc->errors);
				else
					fprintf(outf, "%*s", cwidths[c], "");
				break;
			PC_(CSC_SC_NAME,    sysent[idx].sys_name)
			}
		}
		fputc('\n', outf);
	}

	free(indices);

	/* footer */
	for (size_t i = 0; i <= last_column; i++) {
		if (i)
			fputc(' ', outf);

		for (size_t j = 0; j < cwidths[columns[i]]; j++)
			fputc('-', outf);
	}
	fputc('\n', outf);

	/* totals */
	for (size_t i = 0; i <= last_column; i++) {
		const size_t c = columns[i];
		if (i)
			fputc(' ', outf);

		switch (c) {
		PC_(CSC_TIME_100S, 100.0)
		PC_(CSC_TIME_TOTAL, float_tv_cum)
		PC_(CSC_TIME_AVG,
		    (uint64_t) (float_tv_cum / call_cum * 1e6))
		PC_(CSC_CALLS, call_cum)
		PC_(CSC_ERRORS, error_cum)
		PC_(CSC_SC_NAME, "total")
		}
	}
	fputc('\n', outf);

#undef PC_
}

void
call_summary(FILE *outf)
{
	unsigned int i, old_pers = current_personality;

	for (i = 0; i < SUPPORTED_PERSONALITIES; ++i) {
		if (!countv[i])
			continue;

		if (current_personality != i)
			set_personality(i);
		if (i)
			fprintf(outf,
				"System call usage summary for %s mode:\n",
				personality_names[i]);
		call_summary_pers(outf);
	}

	if (old_pers != current_personality)
		set_personality(old_pers);
}
