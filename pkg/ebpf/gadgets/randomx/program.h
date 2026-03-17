#pragma once

#include <gadget/filesystem.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    bool upper_layer;
    __u32 mxcsr_raw;
    char exepath[GADGET_PATH_MAX];
};
