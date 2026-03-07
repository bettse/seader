#include "trace_log.h"

#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>

static void seader_trace_write(FS_OpenMode open_mode, const char* line) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, STORAGE_APP_DATA_PATH_PREFIX);

    Stream* stream = buffered_file_stream_alloc(storage);
    if(buffered_file_stream_open(stream, SEADER_TRACE_FILE_NAME, FSAM_READ_WRITE, open_mode)) {
        stream_seek(stream, 0, StreamOffsetFromEnd);
        stream_write(stream, (const uint8_t*)line, strlen(line));
    }

    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);
}

void seader_trace_reset(void) {
    seader_trace_write(FSOM_CREATE_ALWAYS, "");
}

void seader_trace(const char* tag, const char* fmt, ...) {
    char message[192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    char line[224];
    snprintf(line, sizeof(line), "[%s] %s\n", tag, message);
    seader_trace_write(FSOM_OPEN_ALWAYS, line);
}
