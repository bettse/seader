#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct Seader Seader;
typedef struct SeaderPollerContainer SeaderPollerContainer;

bool seader_worker_acquire(Seader* seader);
void seader_worker_release(Seader* seader);
void seader_scratch_reset(Seader* seader);
void* seader_scratch_alloc(Seader* seader, size_t size, size_t align);
bool seader_wiegand_plugin_acquire(Seader* seader);
void seader_wiegand_plugin_release(Seader* seader);
