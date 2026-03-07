#pragma once

#include <stdarg.h>

#define SEADER_TRACE_FILE_NAME APP_DATA_PATH("trace.log")

void seader_trace_reset(void);
void seader_trace(const char* tag, const char* fmt, ...);
