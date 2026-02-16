// SPDX-License-Identifier: GPL-2.0

#pragma once

#include <gadget/types.h>
#include <gadget/user_stack_map.h>
#include <gadget/filesystem.h>

#define NAME_MAX 255

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	gadget_errno error_raw;
	__u32 fd;
	gadget_file_flags flags_raw;
	gadget_file_mode mode_raw;
	struct gadget_user_stack ustack;
	char fname[NAME_MAX];
	char fpath[GADGET_PATH_MAX];
};
