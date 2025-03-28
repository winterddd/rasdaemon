/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __RAS_NON_STANDARD_HANDLER_H
#define __RAS_NON_STANDARD_HANDLER_H

#include <traceevent/event-parse.h>

#include "ras-events.h"
#include "ras-record.h"

#ifdef HAVE_SQLITE3
#include <sqlite3.h>
#endif

struct ras_ns_ev_decoder {
	struct ras_ns_ev_decoder *next;
	uint16_t ref_count;
	const char *sec_type;
	int (*add_table)(struct ras_events *ras, struct ras_ns_ev_decoder *ev_decoder);
	int (*decode)(struct ras_events *ras, struct ras_ns_ev_decoder *ev_decoder,
		      struct trace_seq *s, struct ras_non_standard_event *event);
#ifdef HAVE_SQLITE3
	sqlite3_stmt *stmt_dec_record;
#endif
};

int ras_non_standard_event_handler(struct trace_seq *s,
				   struct tep_record *record,
				   struct tep_event *event, void *context);

void print_le_hex(struct trace_seq *s, const uint8_t *buf, int index);

#ifdef HAVE_NON_STANDARD
int register_ns_ev_decoder(struct ras_ns_ev_decoder *ns_ev_decoder);
int ras_ns_add_vendor_tables(struct ras_events *ras);
void ras_ns_finalize_vendor_tables(void);
#else
static inline int register_ns_ev_decoder(struct ras_ns_ev_decoder *ns_ev_decoder) { return 0; };
#endif

#endif
