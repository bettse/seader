#include "apdu_runner.h"

#define TAG "APDU_Runner"

// Max length of firmware upgrade: 731 bytes
#define SEADER_APDU_MAX_LEN 732

void seader_apdu_runner_cleanup(Seader* seader, SeaderWorkerEvent event) {
    SeaderWorker* seader_worker = seader->worker;
    seader_worker_change_state(seader_worker, SeaderWorkerStateReady);
    apdu_log_free(seader->apdu_log);
    seader->apdu_log = NULL;
    if(seader_worker->callback) {
        seader_worker->callback(event, seader_worker->context);
    }
}

bool seader_apdu_runner_send_next_line(Seader* seader) {
    SeaderWorker* seader_worker = seader->worker;
    SeaderUartBridge* seader_uart = seader_worker->uart;
    SeaderAPDURunnerContext* apdu_runner_ctx = &(seader->apdu_runner_ctx);

    FuriString* line = furi_string_alloc();
    apdu_log_get_next_log_str(seader->apdu_log, line);

    size_t len = furi_string_size(line) / 2; // String is in HEX, divide by 2 for bytes
    uint8_t* apdu = malloc(len);
    if(apdu == NULL) {
        FURI_LOG_E(TAG, "Failed to allocate memory for APDU");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        return false;
    }

    if(len > SEADER_UART_RX_BUF_SIZE) {
        FURI_LOG_E(TAG, "APDU length is too long");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        free(apdu);
        return false;
    }

    if(!hex_chars_to_uint8(furi_string_get_cstr(line), apdu)) {
        FURI_LOG_E(TAG, "Failed to convert line to number");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        free(apdu);
        return false;
    }
    FURI_LOG_I(
        TAG,
        "APDU Runner => (%d/%d): %s",
        apdu_runner_ctx->current_line + 1,
        apdu_runner_ctx->total_lines,
        furi_string_get_cstr(line));

    if(seader_worker->callback) {
        seader_worker->callback(SeaderWorkerEventAPDURunnerUpdate, seader_worker->context);
    }

    apdu_runner_ctx->current_line++;
    if(seader_uart->T == 1) {
        seader_send_t1(seader_uart, apdu, len);
    } else {
        seader_ccid_XfrBlock(seader_uart, apdu, len);
    }
    furi_string_free(line);
    free(apdu);

    return true;
}

void seader_apdu_runner_init(Seader* seader) {
    SeaderAPDURunnerContext* apdu_runner_ctx = &(seader->apdu_runner_ctx);

    if(apdu_log_check_presence(SEADER_APDU_RUNNER_FILE_NAME)) {
        FURI_LOG_I(TAG, "APDU log file exists");
    } else {
        FURI_LOG_W(TAG, "APDU log file does not exist");
        return;
    }

    seader->apdu_log = apdu_log_alloc(SEADER_APDU_RUNNER_FILE_NAME, APDULogModeOpenExisting);
    apdu_runner_ctx->current_line = 0;
    apdu_runner_ctx->total_lines = apdu_log_get_total_lines(seader->apdu_log);
    FURI_LOG_I(TAG, "APDU log lines: %d", apdu_runner_ctx->total_lines);

    seader_apdu_runner_send_next_line(seader);
}

bool seader_apdu_runner_response(Seader* seader, uint8_t* r_apdu, size_t r_len) {
    SeaderUartBridge* seader_uart = seader->worker->uart;
    SeaderAPDURunnerContext* apdu_runner_ctx = &(seader->apdu_runner_ctx);
    uint8_t GET_RESPONSE[] = {0x00, 0xc0, 0x00, 0x00, 0xff};

    uint8_t SW1 = r_apdu[r_len - 2];
    uint8_t SW2 = r_apdu[r_len - 1];

    switch(SW1) {
    case 0x61:
        //FURI_LOG_D(TAG, "Request %d bytes", SW2);
        GET_RESPONSE[4] = SW2;
        seader_ccid_XfrBlock(seader_uart, GET_RESPONSE, sizeof(GET_RESPONSE));
        return true;
    }

    if(r_len < SEADER_UART_RX_BUF_SIZE) {
        char* display = malloc(r_len * 2 + 1);
        if(display == NULL) {
            FURI_LOG_E(TAG, "Failed to allocate memory for display");
            seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
            return false;
        }
        memset(display, 0, r_len * 2 + 1);
        for(uint8_t i = 0; i < r_len; i++) {
            snprintf(display + (i * 2), sizeof(display), "%02x", r_apdu[i]);
        }
        FURI_LOG_I(
            TAG,
            "APDU Runner <=: (%d/%d): %s",
            apdu_runner_ctx->current_line + 1,
            apdu_runner_ctx->total_lines,
            display);
        free(display);
    } else {
        FURI_LOG_I(TAG, "APDU Runner <=: Response too long to display");
    }

    /** Compare last two bytes to expected line **/

    FuriString* line = furi_string_alloc();
    apdu_log_get_next_log_str(seader->apdu_log, line);
    if(furi_string_size(line) % 2 == 1) {
        FURI_LOG_E(TAG, "APDU log file has odd number of characters");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        return false;
    }

    size_t len = furi_string_size(line) / 2; // String is in HEX, divide by 2 for bytes
    uint8_t* apdu = malloc(len);
    if(apdu == NULL) {
        FURI_LOG_E(TAG, "Failed to allocate memory for APDU");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        return false;
    }

    if(!hex_chars_to_uint8(furi_string_get_cstr(line), apdu)) {
        FURI_LOG_E(TAG, "Failed to convert line to byte array");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        free(apdu);
        // TODO: Send failed event
        return false;
    }

    apdu_runner_ctx->current_line++;
    furi_string_free(line);

    if(memcmp(r_apdu + r_len - 2, apdu + len - 2, 2) != 0) {
        FURI_LOG_W(
            TAG,
            "APDU runner response does not match.  Response %02x%02x != expected %02x%02x",
            r_apdu[r_len - 2],
            r_apdu[r_len - 1],
            apdu[len - 2],
            apdu[len - 1]);
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerError);
        free(apdu);
        return false;
    }
    free(apdu);

    // Check if we are at the end of the log
    if(apdu_runner_ctx->current_line >= apdu_runner_ctx->total_lines) {
        FURI_LOG_I(TAG, "APDU runner finished");
        seader_apdu_runner_cleanup(seader, SeaderWorkerEventAPDURunnerSuccess);
        return false;
    }

    // Send next line
    return seader_apdu_runner_send_next_line(seader);
}
