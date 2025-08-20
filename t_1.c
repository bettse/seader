#include "t_1.h"

#define TAG "Seader:T=1"

// http://www.sat-digest.com/SatXpress/SmartCard/ISO7816-4.htm

/* I know my T=1 is terrible, but I'm also only targetting one specific 'card' */

#define MORE_BIT               0x20
#define IFSD_VALUE             0xfe
#define IFSC_VALUE             0xfe // Fom the SAM ATR
#define R_BLOCK                0x80
#define R_SEQUENCE_NUMBER_MASK 0x10

// TODO: T1 struct
uint8_t NAD = 0x00;
uint8_t dPCB = 0x40; // Init to 0x40 so first call to next_pcb will return 0x00
uint8_t cPCB = 0x00; // Init to 0x40 so first call to next_pcb will return 0x00

uint8_t seader_next_dpcb() {
    uint8_t next_pcb = dPCB ^ 0x40;
    //FURI_LOG_D(TAG, "dPCB was: %02X, current dPCB: %02X", dPCB, next_pcb);
    dPCB = next_pcb;
    return dPCB;
}

uint8_t seader_next_cpcb() {
    uint8_t next_pcb = cPCB ^ 0x40;
    //FURI_LOG_D(TAG, "cPCB was: %02X, current cPCB: %02X", cPCB, next_pcb);
    cPCB = next_pcb;
    return cPCB;
}

void seader_t_1_reset() {
    NAD = 0x00;
    dPCB = 0x40;
    cPCB = 0x00;
}

void seader_t_1_set_IFSD(Seader* seader) {
    SeaderWorker* seader_worker = seader->worker;
    SeaderUartBridge* seader_uart = seader_worker->uart;
    uint8_t frame[5];
    uint8_t frame_len = 0;

    frame[0] = NAD;
    frame[1] = 0xC1; // S(IFS request)
    frame[2] = 0x01;
    frame[3] = IFSD_VALUE;
    frame_len = 4;

    frame_len = seader_add_lrc(frame, frame_len);

    seader_ccid_XfrBlock(seader_uart, frame, frame_len);
}

void seader_t_1_send_ack(Seader* seader) {
    SeaderWorker* seader_worker = seader->worker;
    SeaderUartBridge* seader_uart = seader_worker->uart;
    uint8_t frame[4];
    uint8_t frame_len = 0;

    frame[0] = NAD;
    frame[1] = R_BLOCK | (seader_next_cpcb() >> 2);
    frame[2] = 0x00;
    frame_len = 3;

    frame_len = seader_add_lrc(frame, frame_len);

    //FURI_LOG_D(TAG, "Sending R-Block ACK: PCB: %02x", frame[1]);

    seader_ccid_XfrBlock(seader_uart, frame, frame_len);
}

BitBuffer* seader_t_1_tx_buffer;
size_t seader_t_1_tx_buffer_offset = 0;

void seader_send_t1_chunk(SeaderUartBridge* seader_uart, uint8_t PCB, uint8_t* chunk, size_t len) {
    uint8_t* frame = malloc(3 + len + 1);
    uint8_t frame_len = 0;

    frame[0] = NAD;
    frame[1] = PCB;
    frame[2] = len;
    frame_len = 3;

    if(len > 0) {
        memcpy(frame + frame_len, chunk, len);
        frame_len += len;
    }

    frame_len = seader_add_lrc(frame, frame_len);

    seader_ccid_XfrBlock(seader_uart, frame, frame_len);
    free(frame);
}

void seader_send_t1(SeaderUartBridge* seader_uart, uint8_t* apdu, size_t len) {
    if(len > IFSC_VALUE) {
        if(seader_t_1_tx_buffer == NULL) {
            seader_t_1_tx_buffer = bit_buffer_alloc(768);
            bit_buffer_copy_bytes(seader_t_1_tx_buffer, apdu, len);
        }
        size_t remaining =
            (bit_buffer_get_size_bytes(seader_t_1_tx_buffer) - seader_t_1_tx_buffer_offset);
        size_t copy_length = remaining > IFSC_VALUE ? IFSC_VALUE : remaining;

        uint8_t* chunk =
            (uint8_t*)bit_buffer_get_data(seader_t_1_tx_buffer) + seader_t_1_tx_buffer_offset;

        if(remaining > IFSC_VALUE) {
            uint8_t PCB = seader_next_dpcb() | MORE_BIT;
            seader_send_t1_chunk(seader_uart, PCB, chunk, copy_length);
        } else {
            uint8_t PCB = seader_next_dpcb();
            seader_send_t1_chunk(seader_uart, PCB, chunk, copy_length);
        }

        seader_t_1_tx_buffer_offset += copy_length;
        if(seader_t_1_tx_buffer_offset >= bit_buffer_get_size_bytes(seader_t_1_tx_buffer)) {
            bit_buffer_free(seader_t_1_tx_buffer);
            seader_t_1_tx_buffer = NULL;
            seader_t_1_tx_buffer_offset = 0;
        }
        return;
    }

    seader_send_t1_chunk(seader_uart, seader_next_dpcb(), apdu, len);
}

BitBuffer* seader_t_1_rx_buffer;

bool seader_recv_t1(Seader* seader, CCID_Message* message) {
    // remove/validate NAD, PCB, LEN, LRC
    if(message->dwLength < 4) {
        FURI_LOG_W(TAG, "Invalid T=1 frame: too short");
        return false;
    }
    //uint8_t NAD = message->payload[0];
    uint8_t rPCB = message->payload[1];
    uint8_t LEN = message->payload[2];
    //uint8_t LRC = message->payload[3 + LEN];
    //FURI_LOG_D(TAG, "NAD: %02X, rPCB: %02X, LEN: %02X, LRC: %02X", NAD, rPCB, LEN, LRC);

    if(rPCB == 0xE1) {
        // S(IFS response)
        seader_worker_send_version(seader);
        SeaderWorker* seader_worker = seader->worker;
        if(seader_worker->callback) {
            seader_worker->callback(SeaderWorkerEventSamPresent, seader_worker->context);
        }
        return false;
    }

    if(rPCB == cPCB) {
        seader_next_cpcb();
        if(seader_t_1_rx_buffer != NULL) {
            bit_buffer_append_bytes(seader_t_1_rx_buffer, message->payload + 3, LEN);

            // TODO: validate LRC

            seader_worker_process_sam_message(
                seader,
                (uint8_t*)bit_buffer_get_data(seader_t_1_rx_buffer),
                bit_buffer_get_size_bytes(seader_t_1_rx_buffer));

            bit_buffer_free(seader_t_1_rx_buffer);
            seader_t_1_rx_buffer = NULL;
            return true;
        }

        if(seader_validate_lrc(message->payload, message->dwLength) == false) {
            return false;
        }

        // Skip NAD, PCB, LEN
        message->payload = message->payload + 3;
        message->dwLength = LEN;

        if(message->dwLength == 0) {
            //FURI_LOG_D(TAG, "Received T=1 frame with no data");
            return true;
        }
        return seader_worker_process_sam_message(seader, message->payload, message->dwLength);
    } else if(rPCB == (cPCB | MORE_BIT)) {
        //FURI_LOG_D(TAG, "Received T=1 frame with more bit set");
        if(seader_t_1_rx_buffer == NULL) {
            seader_t_1_rx_buffer = bit_buffer_alloc(512);
        }
        bit_buffer_append_bytes(seader_t_1_rx_buffer, message->payload + 3, LEN);
        seader_t_1_send_ack(seader);
        return false;
    } else if((rPCB & R_BLOCK) == R_BLOCK) {
        uint8_t R_SEQ = (rPCB & R_SEQUENCE_NUMBER_MASK) >> 4;
        uint8_t I_SEQ = (dPCB ^ 0x40) >> 6;
        if(R_SEQ != I_SEQ) {
            /*
            FURI_LOG_D(
                TAG,
                "Received R-Block: Incorrect sequence.  Expected: %02X, Received: %02X",
                I_SEQ,
                R_SEQ);

            */
            // When this happens, the flipper freezes if it is doing NFC and my attempts to do events to stop that have failed
            return false;
        }

        if(seader_t_1_tx_buffer != NULL) {
            // Send more data, re-using the buffer to trigger the code path that sends the next block
            SeaderWorker* seader_worker = seader->worker;
            SeaderUartBridge* seader_uart = seader_worker->uart;
            seader_send_t1(
                seader_uart,
                (uint8_t*)bit_buffer_get_data(seader_t_1_tx_buffer),
                bit_buffer_get_size_bytes(seader_t_1_tx_buffer));
            return false;
        }
    } else {
        FURI_LOG_W(
            TAG, "Invalid T=1 frame: PCB mismatch.  Expected: %02X, Received: %02X", cPCB, rPCB);
    }

    return false;
}
