#include "sam_api.h"
#include <toolbox/path.h>
#include <toolbox/version.h>
#include <bit_lib/bit_lib.h>

//#define ASN1_DEBUG                      true

#define TAG "SAMAPI"

#define ASN1_PREFIX                     6
#define SEADER_ICLASS_SR_SIO_BASE_BLOCK 10
#define SEADER_SERIAL_FILE_NAME         "sam_serial"

const uint8_t picopass_iclass_key[] = {0xaf, 0xa7, 0x85, 0xa7, 0xda, 0xb3, 0x33, 0x78};

static char display[SEADER_UART_RX_BUF_SIZE * 2 + 1] = {0};

#ifdef ASN1_DEBUG
char asn1_log[SEADER_UART_RX_BUF_SIZE] = {0};
#endif

uint8_t updateBlock2[] = {RFAL_PICOPASS_CMD_UPDATE, 0x02};

uint8_t ev2_request[] =
    {0x00, 0xa4, 0x04, 0x00, 0x0a, 0xa0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00};
uint8_t FILE_NOT_FOUND[] = {0x6a, 0x82};

void* calloc(size_t count, size_t size) {
    return malloc(count * size);
}

// Forward declarations
void seader_send_nfc_rx(Seader* seader, uint8_t* buffer, size_t len);

PicopassError seader_worker_fake_epurse_update(BitBuffer* tx_buffer, BitBuffer* rx_buffer) {
    const uint8_t* buffer = bit_buffer_get_data(tx_buffer);
    uint8_t fake_response[8];
    memset(fake_response, 0, sizeof(fake_response));
    memcpy(fake_response + 0, buffer + 6, 4);
    memcpy(fake_response + 4, buffer + 2, 4);

    bit_buffer_append_bytes(rx_buffer, fake_response, sizeof(fake_response));
    iso13239_crc_append(Iso13239CrcTypePicopass, rx_buffer);

    memset(display, 0, sizeof(display));
    for(uint8_t i = 0; i < bit_buffer_get_size_bytes(rx_buffer); i++) {
        snprintf(display + (i * 2), sizeof(display), "%02x", bit_buffer_get_data(rx_buffer)[i]);
    }
    FURI_LOG_I(TAG, "Fake update E-Purse response: %s", display);

    return PicopassErrorNone;
}

void seader_picopass_state_machine(Seader* seader, uint8_t* buffer, size_t len) {
    BitBuffer* tx_buffer = bit_buffer_alloc(len);
    bit_buffer_append_bytes(tx_buffer, buffer, len);
    BitBuffer* rx_buffer = bit_buffer_alloc(SEADER_POLLER_MAX_BUFFER_SIZE);

    uint8_t config[PICOPASS_BLOCK_LEN] = {0x12, 0xff, 0xff, 0xff, 0x7f, 0x1f, 0xff, 0x3c};
    uint8_t sr_aia[PICOPASS_BLOCK_LEN] = {0xFF, 0xff, 0xff, 0xff, 0xFF, 0xFf, 0xff, 0xFF};
    uint8_t epurse[PICOPASS_BLOCK_LEN] = {0xff, 0xff, 0xff, 0xff, 0xe3, 0xff, 0xff, 0xff};
    uint8_t pacs_sr_cfg[PICOPASS_BLOCK_LEN] = {0xA3, 0x03, 0x03, 0x03, 0x00, 0x03, 0xe0, 0x14};
    uint8_t zeroes[PICOPASS_BLOCK_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t tmac[4] = {};
    uint8_t cc_p[12] = {};
    uint8_t div_key[PICOPASS_BLOCK_LEN] = {};
    uint8_t offset; // for READ4

    do {
        switch(buffer[0]) {
        case RFAL_PICOPASS_CMD_READ_OR_IDENTIFY:
            if(buffer[1] == AIA_INDEX) {
                bit_buffer_append_bytes(rx_buffer, sr_aia, sizeof(sr_aia));
            } else if(buffer[1] == PACS_CFG_INDEX) {
                bit_buffer_append_bytes(rx_buffer, pacs_sr_cfg, sizeof(pacs_sr_cfg));
            } else { // What i've seen is 0c 12
                offset = buffer[1] - SEADER_ICLASS_SR_SIO_BASE_BLOCK;
                bit_buffer_append_bytes(
                    rx_buffer,
                    seader->credential->sio + (PICOPASS_BLOCK_LEN * offset),
                    PICOPASS_BLOCK_LEN);
            }
            iso13239_crc_append(Iso13239CrcTypePicopass, rx_buffer);
            break;
        case RFAL_PICOPASS_CMD_UPDATE:
            seader_worker_fake_epurse_update(tx_buffer, rx_buffer);
            break;
        case RFAL_PICOPASS_CMD_READCHECK_KD:
            if(buffer[1] == EPURSE_INDEX) {
                bit_buffer_append_bytes(rx_buffer, epurse, sizeof(epurse));
            }
            break;
        case RFAL_PICOPASS_CMD_CHECK:
            loclass_iclass_calc_div_key(
                seader->credential->diversifier, picopass_iclass_key, div_key, false);
            memcpy(cc_p, epurse, PICOPASS_BLOCK_LEN);
            memcpy(cc_p + 8, buffer + 1, PICOPASS_MAC_LEN);
            loclass_opt_doTagMAC(cc_p, div_key, tmac);
            bit_buffer_append_bytes(rx_buffer, tmac, sizeof(tmac));
            break;
        case RFAL_PICOPASS_CMD_READ4:
            if(buffer[1] < SEADER_ICLASS_SR_SIO_BASE_BLOCK) {
                if(buffer[1] == PACS_CFG_INDEX) {
                    bit_buffer_append_bytes(rx_buffer, pacs_sr_cfg, sizeof(pacs_sr_cfg));
                    bit_buffer_append_bytes(rx_buffer, zeroes, sizeof(zeroes));
                    bit_buffer_append_bytes(rx_buffer, zeroes, sizeof(zeroes));
                    bit_buffer_append_bytes(rx_buffer, zeroes, sizeof(zeroes));
                }
            } else {
                offset = buffer[1] - SEADER_ICLASS_SR_SIO_BASE_BLOCK;
                bit_buffer_append_bytes(
                    rx_buffer,
                    seader->credential->sio + (PICOPASS_BLOCK_LEN * offset),
                    PICOPASS_BLOCK_LEN * 4);
            }
            iso13239_crc_append(Iso13239CrcTypePicopass, rx_buffer);
            break;
        case RFAL_PICOPASS_CMD_PAGESEL:
            // this should be considered an attempt, but realisticly not working
            bit_buffer_append_bytes(rx_buffer, config, sizeof(config));
            iso13239_crc_append(Iso13239CrcTypePicopass, rx_buffer);
            break;
        }

        seader_send_nfc_rx(
            seader,
            (uint8_t*)bit_buffer_get_data(rx_buffer),
            bit_buffer_get_size_bytes(rx_buffer));

    } while(false);
    bit_buffer_free(tx_buffer);
    bit_buffer_free(rx_buffer);
}

uint8_t APDU_HEADER_LEN = 5;
bool seader_send_apdu(
    Seader* seader,
    uint8_t CLA,
    uint8_t INS,
    uint8_t P1,
    uint8_t P2,
    uint8_t* payload,
    uint8_t payloadLen) {
    SeaderWorker* seader_worker = seader->worker;
    SeaderUartBridge* seader_uart = seader_worker->uart;

    if(seader_uart->T == 1) {
        APDU_HEADER_LEN = 7;
    }

    if(APDU_HEADER_LEN + payloadLen > SEADER_UART_RX_BUF_SIZE) {
        FURI_LOG_E(TAG, "Cannot send message, too long: %d", APDU_HEADER_LEN + payloadLen);
        return false;
    }

    uint8_t length = APDU_HEADER_LEN + payloadLen;
    uint8_t* apdu = malloc(length);
    if(!apdu) {
        FURI_LOG_E(TAG, "Failed to allocate memory for apdu in seader_send_apdu");
        return false;
    }

    apdu[0] = CLA;
    apdu[1] = INS;
    apdu[2] = P1;
    apdu[3] = P2;

    if(seader_uart->T == 1) {
        apdu[4] = 0x00;
        apdu[5] = 0x00;
        apdu[6] = payloadLen;
    } else {
        apdu[4] = payloadLen;
    }

    memcpy(apdu + APDU_HEADER_LEN, payload, payloadLen);

    memset(display, 0, sizeof(display));
    for(uint8_t i = 0; i < length; i++) {
        snprintf(display + (i * 2), sizeof(display), "%02x", apdu[i]);
    }
    FURI_LOG_D(TAG, "seader_send_apdu %s", display);

    if(seader_uart->T == 1) {
        seader_send_t1(seader_uart, apdu, length);
    } else {
        seader_ccid_XfrBlock(seader_uart, apdu, length);
    }
    free(apdu);

    return true;
}

#ifdef ASN1_DEBUG
static int seader_print_struct_callback(const void* buffer, size_t size, void* app_key) {
    if(app_key) {
        char* str = (char*)app_key;
        size_t next = strlen(str);
        strncpy(str + next, buffer, size);
    } else {
        uint8_t next = strlen(asn1_log);
        strncpy(asn1_log + next, buffer, size);
    }
    return 0;
}
#else
static int seader_print_struct_callback(const void* buffer, size_t size, void* app_key) {
    UNUSED(buffer);
    UNUSED(size);
    UNUSED(app_key);
    return 0;
}
#endif

void seader_send_payload(
    Seader* seader,
    Payload_t* payload,
    uint8_t to,
    uint8_t from,
    uint8_t replyTo) {
    uint8_t rBuffer[SEADER_UART_RX_BUF_SIZE] = {0};

    asn_enc_rval_t er = der_encode_to_buffer(
        &asn_DEF_Payload, payload, rBuffer + ASN1_PREFIX, sizeof(rBuffer) - ASN1_PREFIX);

#ifdef ASN1_DEBUG
    if(er.encoded > -1) {
        char payloadDebug[1024] = {0};
        memset(payloadDebug, 0, sizeof(payloadDebug));
        (&asn_DEF_Payload)
            ->op->print_struct(
                &asn_DEF_Payload, payload, 1, seader_print_struct_callback, payloadDebug);
        if(strlen(payloadDebug) > 0) {
            FURI_LOG_D(TAG, "Sending payload[%d %d %d]: %s", to, from, replyTo, payloadDebug);
        }
    } else {
        FURI_LOG_W(TAG, "Failed to print_struct payload");
    }
#endif
    //0xa0, 0xda, 0x02, 0x63, 0x00, 0x00, 0x0a,
    //0x44, 0x0a, 0x44, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x96, 0x00
    rBuffer[0] = to;
    rBuffer[1] = from;
    rBuffer[2] = replyTo;

    seader_send_apdu(seader, 0xA0, 0xDA, 0x02, 0x63, rBuffer, 6 + er.encoded);
}

void seader_send_response(
    Seader* seader,
    Response_t* response,
    uint8_t to,
    uint8_t from,
    uint8_t replyTo) {
    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);

    payload->present = Payload_PR_response;
    payload->choice.response = *response;

    seader_send_payload(seader, payload, to, from, replyTo);

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
}

void seader_send_request_pacs(Seader* seader) {
    RequestPacs_t* requestPacs = 0;
    requestPacs = calloc(1, sizeof *requestPacs);
    assert(requestPacs);

    requestPacs->contentElementTag = ContentElementTag_implicitFormatPhysicalAccessBits;

    SamCommand_t* samCommand = 0;
    samCommand = calloc(1, sizeof *samCommand);
    assert(samCommand);

    samCommand->present = SamCommand_PR_requestPacs;
    seader->samCommand = samCommand->present;

    samCommand->choice.requestPacs = *requestPacs;

    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);

    payload->present = Payload_PR_samCommand;
    payload->choice.samCommand = *samCommand;

    seader_send_payload(seader, payload, ExternalApplicationA, SAMInterface, ExternalApplicationA);

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
    ASN_STRUCT_FREE(asn_DEF_SamCommand, samCommand);
    ASN_STRUCT_FREE(asn_DEF_RequestPacs, requestPacs);
}

void seader_worker_send_serial_number(Seader* seader) {
    SamCommand_t* samCommand = 0;
    samCommand = calloc(1, sizeof *samCommand);
    assert(samCommand);

    samCommand->present = SamCommand_PR_serialNumber;
    seader->samCommand = samCommand->present;

    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);

    payload->present = Payload_PR_samCommand;
    payload->choice.samCommand = *samCommand;

    seader_send_payload(seader, payload, ExternalApplicationA, SAMInterface, ExternalApplicationA);

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
    ASN_STRUCT_FREE(asn_DEF_SamCommand, samCommand);
}

void seader_worker_send_version(Seader* seader) {
    SamCommand_t* samCommand = 0;
    samCommand = calloc(1, sizeof *samCommand);
    assert(samCommand);

    samCommand->present = SamCommand_PR_version;
    seader->samCommand = samCommand->present;

    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);

    payload->present = Payload_PR_samCommand;
    payload->choice.samCommand = *samCommand;

    seader_send_payload(seader, payload, ExternalApplicationA, SAMInterface, ExternalApplicationA);

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
    ASN_STRUCT_FREE(asn_DEF_SamCommand, samCommand);
}

void seader_send_card_detected(Seader* seader, CardDetails_t* cardDetails) {
    CardDetected_t* cardDetected = 0;
    cardDetected = calloc(1, sizeof *cardDetected);
    assert(cardDetected);

    cardDetected->detectedCardDetails = *cardDetails;

    SamCommand_t* samCommand = 0;
    samCommand = calloc(1, sizeof *samCommand);
    assert(samCommand);

    samCommand->present = SamCommand_PR_cardDetected;
    seader->samCommand = samCommand->present;
    samCommand->choice.cardDetected = *cardDetected;

    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);

    payload->present = Payload_PR_samCommand;
    payload->choice.samCommand = *samCommand;

    seader_send_payload(seader, payload, ExternalApplicationA, SAMInterface, ExternalApplicationA);

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
    ASN_STRUCT_FREE(asn_DEF_SamCommand, samCommand);
    ASN_STRUCT_FREE(asn_DEF_CardDetected, cardDetected);
}

bool seader_unpack_pacs(Seader* seader, uint8_t* buf, size_t size) {
    SeaderCredential* seader_credential = seader->credential;
    PAC_t* pac = 0;
    pac = calloc(1, sizeof *pac);
    assert(pac);
    bool rtn = false;

    asn_dec_rval_t rval = asn_decode(0, ATS_DER, &asn_DEF_PAC, (void**)&pac, buf, size);

    if(rval.code == RC_OK) {
#ifdef ASN1_DEBUG
        char pacDebug[384] = {0};
        (&asn_DEF_PAC)
            ->op->print_struct(&asn_DEF_PAC, pac, 1, seader_print_struct_callback, pacDebug);
        if(strlen(pacDebug) > 0) {
            FURI_LOG_D(TAG, "Received pac: %s", pacDebug);
        }
#endif

        memset(display, 0, sizeof(display));
        if(seader_credential->sio[0] == 0x30) {
            for(uint8_t i = 0; i < seader_credential->sio_len; i++) {
                snprintf(display + (i * 2), sizeof(display), "%02x", seader_credential->sio[i]);
            }
            FURI_LOG_D(TAG, "SIO %s", display);

#ifdef ASN1_DEBUG
            SIO_t* sio = 0;
            sio = calloc(1, sizeof *sio);
            assert(sio);
            rval = asn_decode(
                0,
                ATS_DER,
                &asn_DEF_SIO,
                (void**)&sio,
                seader_credential->sio,
                seader_credential->sio_len);

            if(rval.code == RC_OK) {
                FURI_LOG_D(TAG, "Decoded SIO");
                char sioDebug[384] = {0};
                (&asn_DEF_SIO)
                    ->op->print_struct(
                        &asn_DEF_SIO, sio, 1, seader_print_struct_callback, sioDebug);
                if(strlen(sioDebug) > 0) {
                    FURI_LOG_D(TAG, "SIO: %s", sioDebug);
                }
            } else {
                FURI_LOG_W(TAG, "Failed to decode SIO %d consumed", rval.consumed);
            }

            ASN_STRUCT_FREE(asn_DEF_SIO, sio);
#endif
        }

        if(pac->size <= sizeof(seader_credential->credential)) {
            // TODO: make credential into a 12 byte array
            seader_credential->bit_length = pac->size * 8 - pac->bits_unused;
            memcpy(&seader_credential->credential, pac->buf, pac->size);
            seader_credential->credential = __builtin_bswap64(seader_credential->credential);
            seader_credential->credential = seader_credential->credential >>
                                            (64 - seader_credential->bit_length);

            FURI_LOG_D(
                TAG,
                "credential (%d) %016llx",
                seader_credential->bit_length,
                seader_credential->credential);

            rtn = true;
        } else {
            // PACS too big (probably bad data)
            view_dispatcher_send_custom_event(
                seader->view_dispatcher, SeaderCustomEventWorkerExit);
        }
    }

    ASN_STRUCT_FREE(asn_DEF_PAC, pac);
    return rtn;
}

//    800201298106683d052026b6820101
//300F800201298106683D052026B6820101
bool seader_parse_version(SeaderWorker* seader_worker, uint8_t* buf, size_t size) {
    bool rtn = false;
    if(size > 30) {
        // Too large to handle now
        FURI_LOG_W(TAG, "Version of %d is to long to parse", size);
        return false;
    }
    SamVersion_t* version = 0;
    version = calloc(1, sizeof *version);
    assert(version);

    // Add sequence prefix
    uint8_t seq[32] = {0x30};
    seq[1] = (uint8_t)size;
    memcpy(seq + 2, buf, size);

    asn_dec_rval_t rval =
        asn_decode(0, ATS_DER, &asn_DEF_SamVersion, (void**)&version, seq, size + 2);

    if(rval.code == RC_OK) {
        char versionDebug[128] = {0};
        (&asn_DEF_SamVersion)
            ->op->print_struct(
                &asn_DEF_SamVersion, version, 1, seader_print_struct_callback, versionDebug);
        if(strlen(versionDebug) > 0) {
            FURI_LOG_D(TAG, "Received version: %s", versionDebug);
        }
        if(version->version.size == 2) {
            memcpy(seader_worker->sam_version, version->version.buf, version->version.size);
        }

        rtn = true;
    }

    ASN_STRUCT_FREE(asn_DEF_SamVersion, version);
    return rtn;
}

bool seader_sam_save_serial(Seader* seader, uint8_t* buf, size_t size) {
    SeaderCredential* cred = seader->credential;

    const char* file_header = "SAM Serial Number";
    const uint32_t file_version = 1;
    bool use_load_path = true;
    bool saved = false;
    FlipperFormat* file = flipper_format_file_alloc(cred->storage);
    FuriString* temp_str;
    temp_str = furi_string_alloc();

    do {
        if(use_load_path && !furi_string_empty(cred->load_path)) {
            // Get directory name
            path_extract_dirname(furi_string_get_cstr(cred->load_path), temp_str);
            // Make path to file to save
            furi_string_cat_printf(temp_str, "/%s%s", SEADER_SERIAL_FILE_NAME, ".txt");
        } else {
            furi_string_printf(
                temp_str, "%s/%s%s", STORAGE_APP_DATA_PATH_PREFIX, SEADER_SERIAL_FILE_NAME, ".txt");
        }
        // Open file
        if(!flipper_format_file_open_always(file, furi_string_get_cstr(temp_str))) break;
        if(!flipper_format_write_header_cstr(file, file_header, file_version)) break;

        if(!flipper_format_write_hex(file, "Chip Serial Number", buf, size)) break;
        saved = true;
    } while(false);

    if(!saved) {
        dialog_message_show_storage_error(cred->dialogs, "Can not save\nserial file");
    }
    furi_string_free(temp_str);
    flipper_format_free(file);
    return saved;
}

bool seader_sam_save_serial_QR(Seader* seader, char* serial) {
    SeaderCredential* cred = seader->credential;

    const char* file_header = "QRCode";
    const uint32_t file_version = 0;

    bool saved = false;
    FlipperFormat* file = flipper_format_file_alloc(cred->storage);
    FuriString* temp_str;
    temp_str = furi_string_alloc();

    do {
        storage_simply_mkdir(cred->storage, EXT_PATH("qrcodes"));
        furi_string_printf(
            temp_str, "%s/%s%s", EXT_PATH("qrcodes"), "seader_sam_serial", ".qrcode");

        // Open file
        if(!flipper_format_file_open_always(file, furi_string_get_cstr(temp_str))) break;
        if(!flipper_format_write_header_cstr(file, file_header, file_version)) break;

        if(!flipper_format_write_string_cstr(file, "Message", serial)) break;
        saved = true;
    } while(false);

    if(!saved) {
        dialog_message_show_storage_error(cred->dialogs, "Can not save\nQR file");
    }
    furi_string_free(temp_str);
    flipper_format_free(file);
    return saved;
}

bool seader_parse_serial_number(Seader* seader, uint8_t* buf, size_t size) {
    memset(display, 0, sizeof(display));
    for(uint8_t i = 0; i < size; i++) {
        snprintf(display + (i * 2), sizeof(display), "%02x", buf[i]);
    }

    FURI_LOG_D(TAG, "Received serial: %s", display);

    seader_sam_save_serial_QR(seader, display);
    return seader_sam_save_serial(seader, buf, size);
}

bool seader_parse_sam_response(Seader* seader, SamResponse_t* samResponse) {
    SeaderWorker* seader_worker = seader->worker;

    switch(seader->samCommand) {
    case SamCommand_PR_requestPacs:
        FURI_LOG_I(TAG, "samResponse SamCommand_PR_requestPacs");
        seader_unpack_pacs(seader, samResponse->buf, samResponse->size);
        view_dispatcher_send_custom_event(seader->view_dispatcher, SeaderCustomEventPollerSuccess);
        seader->samCommand = SamCommand_PR_NOTHING;
        break;
    case SamCommand_PR_version:
        FURI_LOG_I(TAG, "samResponse SamCommand_PR_version");
        seader_parse_version(seader_worker, samResponse->buf, samResponse->size);
        seader_worker_send_serial_number(seader);
        break;
    case SamCommand_PR_serialNumber:
        FURI_LOG_I(TAG, "samResponse SamCommand_PR_serialNumber");
        seader_parse_serial_number(seader, samResponse->buf, samResponse->size);
        seader->samCommand = SamCommand_PR_NOTHING;
        break;
    case SamCommand_PR_cardDetected:
        FURI_LOG_I(TAG, "samResponse SamCommand_PR_cardDetected");
        seader_send_request_pacs(seader);
        break;
    case SamCommand_PR_NOTHING:
        FURI_LOG_I(TAG, "samResponse SamCommand_PR_NOTHING");
        memset(display, 0, sizeof(display));
        for(uint8_t i = 0; i < samResponse->size; i++) {
            snprintf(display + (i * 2), sizeof(display), "%02x", samResponse->buf[i]);
        }
        FURI_LOG_I(TAG, "Unknown samResponse %d: %s", samResponse->size, display);
        view_dispatcher_send_custom_event(seader->view_dispatcher, SeaderCustomEventWorkerExit);
        break;
    }

    return false;
}

bool seader_parse_response(Seader* seader, Response_t* response) {
    switch(response->present) {
    case Response_PR_samResponse:
        seader_parse_sam_response(seader, &response->choice.samResponse);
        break;
    default:
        FURI_LOG_D(TAG, "non-sam response");
        break;
    };
    return false;
}

void seader_send_nfc_rx(Seader* seader, uint8_t* buffer, size_t len) {
    OCTET_STRING_t rxData = {.buf = buffer, .size = len};
    uint8_t status[] = {0x00, 0x00};
    RfStatus_t rfStatus = {.buf = status, .size = 2};

    NFCRx_t* nfcRx = 0;
    nfcRx = calloc(1, sizeof *nfcRx);
    assert(nfcRx);

    nfcRx->rfStatus = rfStatus;
    nfcRx->data = &rxData;

    NFCResponse_t* nfcResponse = 0;
    nfcResponse = calloc(1, sizeof *nfcResponse);
    assert(nfcResponse);

    nfcResponse->present = NFCResponse_PR_nfcRx;
    nfcResponse->choice.nfcRx = *nfcRx;

    Response_t* response = 0;
    response = calloc(1, sizeof *response);
    assert(response);

    response->present = Response_PR_nfcResponse;
    response->choice.nfcResponse = *nfcResponse;

    seader_send_response(seader, response, NFCInterface, SAMInterface, 0x0);

    ASN_STRUCT_FREE(asn_DEF_NFCRx, nfcRx);
    ASN_STRUCT_FREE(asn_DEF_NFCResponse, nfcResponse);
    ASN_STRUCT_FREE(asn_DEF_Response, response);
}

void seader_capture_sio(BitBuffer* tx_buffer, BitBuffer* rx_buffer, SeaderCredential* credential) {
    const uint8_t* buffer = bit_buffer_get_data(tx_buffer);
    size_t len = bit_buffer_get_size_bytes(tx_buffer);
    const uint8_t* rxBuffer = bit_buffer_get_data(rx_buffer);

    if(credential->type == SeaderCredentialTypePicopass) {
        if(buffer[0] == RFAL_PICOPASS_CMD_READ_OR_IDENTIFY) {
            FURI_LOG_D(TAG, "Picopass Read1 block %02x", buffer[1]);
        }
        if(buffer[0] == RFAL_PICOPASS_CMD_READ4) {
            FURI_LOG_D(TAG, "Picopass Read4 block %02x", buffer[1]);
        }

        if(buffer[0] == RFAL_PICOPASS_CMD_READ4) {
            uint8_t block_num = buffer[1];
            if(credential->sio_len == 0 && rxBuffer[0] == 0x30) {
                credential->sio_start_block = block_num;
            }
            uint8_t offset = (block_num - credential->sio_start_block) * PICOPASS_BLOCK_LEN;
            memcpy(credential->sio + offset, rxBuffer, PICOPASS_BLOCK_LEN * 4);
            credential->sio_len += PICOPASS_BLOCK_LEN * 4;
        }
    } else if(credential->type == SeaderCredentialType14A) {
        // Desfire EV1 passes SIO in the clear
        uint8_t desfire_read[] = {
            0x90, 0xbd, 0x00, 0x00, 0x07, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if(memcmp(buffer, desfire_read, len) == 0 && rxBuffer[0] == 0x30) {
            credential->sio_len =
                bit_buffer_get_size_bytes(rx_buffer) - 2; // -2 for the APDU response bytes
            memcpy(credential->sio, rxBuffer, credential->sio_len);
        }
    }
}

void seader_iso15693_transmit(
    Seader* seader,
    PicopassPoller* picopass_poller,
    uint8_t* buffer,
    size_t len) {
    SeaderWorker* seader_worker = seader->worker;

    BitBuffer* tx_buffer = bit_buffer_alloc(len);
    BitBuffer* rx_buffer = bit_buffer_alloc(SEADER_POLLER_MAX_BUFFER_SIZE);

    PicopassError error = PicopassErrorNone;

    do {
        bit_buffer_append_bytes(tx_buffer, buffer, len);

        if(memcmp(buffer, updateBlock2, sizeof(updateBlock2)) == 0) {
            error = seader_worker_fake_epurse_update(tx_buffer, rx_buffer);
        } else {
            error = picopass_poller_send_frame(
                picopass_poller, tx_buffer, rx_buffer, SEADER_POLLER_MAX_FWT);
        }
        if(error == PicopassErrorIncorrectCrc) {
            error = PicopassErrorNone;
        }

        if(error != PicopassErrorNone) {
            seader_worker->stage = SeaderPollerEventTypeFail;
            break;
        }

        seader_capture_sio(tx_buffer, rx_buffer, seader->credential);
        seader_send_nfc_rx(
            seader,
            (uint8_t*)bit_buffer_get_data(rx_buffer),
            bit_buffer_get_size_bytes(rx_buffer));

    } while(false);

    bit_buffer_free(tx_buffer);
    bit_buffer_free(rx_buffer);
}

/* Assumes this is called in the context of the NFC API callback */
void seader_iso14443a_transmit(
    Seader* seader,
    Iso14443_4aPoller* iso14443_4a_poller,
    uint8_t* buffer,
    size_t len,
    uint16_t timeout,
    uint8_t format[3]) {
    UNUSED(timeout);
    UNUSED(format);

    furi_assert(seader);
    furi_assert(buffer);
    furi_assert(iso14443_4a_poller);
    SeaderWorker* seader_worker = seader->worker;
    SeaderCredential* credential = seader->credential;

    BitBuffer* tx_buffer = bit_buffer_alloc(len);
    BitBuffer* rx_buffer = bit_buffer_alloc(SEADER_POLLER_MAX_BUFFER_SIZE);

    do {
        if(credential->isDesfire && memcmp(buffer, ev2_request, len) == 0) {
            FURI_LOG_I(TAG, "Intercept Desfire EV2 response and return File Not Found");
            bit_buffer_append_bytes(rx_buffer, FILE_NOT_FOUND, sizeof(FILE_NOT_FOUND));

        } else {
            bit_buffer_append_bytes(tx_buffer, buffer, len);

            Iso14443_4aError error =
                iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
            if(error != Iso14443_4aErrorNone) {
                FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
                seader_worker->stage = SeaderPollerEventTypeFail;
                break;
            }
        }

        seader_capture_sio(tx_buffer, rx_buffer, credential);
        seader_send_nfc_rx(
            seader,
            (uint8_t*)bit_buffer_get_data(rx_buffer),
            bit_buffer_get_size_bytes(rx_buffer));

    } while(false);
    bit_buffer_free(tx_buffer);
    bit_buffer_free(rx_buffer);
}

/* Assumes this is called in the context of the NFC API callback */
#define MF_CLASSIC_FWT_FC (60000)
void seader_mfc_transmit(
    Seader* seader,
    MfClassicPoller* mfc_poller,
    uint8_t* buffer,
    size_t len,
    uint16_t timeout,
    uint8_t format[3]) {
    UNUSED(timeout);

    furi_assert(seader);
    furi_assert(buffer);
    furi_assert(mfc_poller);
    SeaderWorker* seader_worker = seader->worker;

    BitBuffer* tx_buffer = bit_buffer_alloc(len);
    BitBuffer* rx_buffer = bit_buffer_alloc(SEADER_POLLER_MAX_BUFFER_SIZE);

    do {
        if(format[0] == 0x00 && format[1] == 0xC0 && format[2] == 0x00) {
            bit_buffer_append_bytes(tx_buffer, buffer, len);
            MfClassicError error =
                mf_classic_poller_send_frame(mfc_poller, tx_buffer, rx_buffer, MF_CLASSIC_FWT_FC);
            if(error != MfClassicErrorNone) {
                FURI_LOG_W(TAG, "mf_classic_poller_send_frame error %d", error);
                seader_worker->stage = SeaderPollerEventTypeFail;
                break;
            }
        } else if(
            (format[0] == 0x00 && format[1] == 0x00 && format[2] == 0x40) ||
            (format[0] == 0x00 && format[1] == 0x00 && format[2] == 0x24) ||
            (format[0] == 0x00 && format[1] == 0x00 && format[2] == 0x44)) {
            memset(display, 0, sizeof(display));
            for(uint8_t i = 0; i < len; i++) {
                snprintf(display + (i * 2), sizeof(display), "%02x", buffer[i]);
            }
            FURI_LOG_D(TAG, "NFC Send with parity %d: %s", len, display);

            // Only handles message up to 8 data bytes
            uint8_t tx_parity = 0;
            uint8_t len_without_parity = len - 1;

            // Don't forget to swap the bits of buffer[8]
            for(size_t i = 0; i < len; i++) {
                bit_lib_reverse_bits(buffer + i, 0, 8);
            }

            // Pull out parity bits
            for(size_t i = 0; i < len_without_parity; i++) {
                bool val = bit_lib_get_bit(buffer + i + 1, i);
                bit_lib_set_bit(&tx_parity, i, val);
            }

            for(size_t i = 0; i < len_without_parity; i++) {
                buffer[i] = (buffer[i] << i) | (buffer[i + 1] >> (8 - i));
            }
            bit_buffer_append_bytes(tx_buffer, buffer, len_without_parity);

            for(size_t i = 0; i < len_without_parity; i++) {
                bit_lib_reverse_bits(buffer + i, 0, 8);
                bit_buffer_set_byte_with_parity(
                    tx_buffer, i, buffer[i], bit_lib_get_bit(&tx_parity, i));
            }

            memset(display, 0, sizeof(display));
            for(uint8_t i = 0; i < bit_buffer_get_size_bytes(tx_buffer); i++) {
                snprintf(
                    display + (i * 2), sizeof(display), "%02x", bit_buffer_get_byte(tx_buffer, i));
            }
            FURI_LOG_D(
                TAG,
                "NFC Send without parity %d: %s [%02x]",
                bit_buffer_get_size_bytes(tx_buffer),
                display,
                tx_parity);

            MfClassicError error = mf_classic_poller_send_custom_parity_frame(
                mfc_poller, tx_buffer, rx_buffer, MF_CLASSIC_FWT_FC);
            if(error != MfClassicErrorNone) {
                FURI_LOG_W(TAG, "mf_classic_poller_send_encrypted_frame error %d", error);
                seader_worker->stage = SeaderPollerEventTypeFail;
                break;
            }

            size_t length = bit_buffer_get_size_bytes(rx_buffer);
            const uint8_t* rx_parity = bit_buffer_get_parity(rx_buffer);

            memset(display, 0, sizeof(display));
            for(uint8_t i = 0; i < length; i++) {
                snprintf(
                    display + (i * 2), sizeof(display), "%02x", bit_buffer_get_byte(rx_buffer, i));
            }
            FURI_LOG_D(
                TAG, "NFC Response without parity %d: %s [%02x]", length, display, rx_parity[0]);

            uint8_t with_parity[SEADER_POLLER_MAX_BUFFER_SIZE];
            memset(with_parity, 0, sizeof(with_parity));

            for(size_t i = 0; i < length; i++) {
                uint8_t b = bit_buffer_get_byte(rx_buffer, i);
                bit_lib_reverse_bits(&b, 0, 8);
                bit_buffer_set_byte(rx_buffer, i, b);
            }

            length = length + (length / 8) + 1;

            uint8_t parts = 1 + length / 9;
            for(size_t p = 0; p < parts; p++) {
                uint8_t doffset = p * 9;
                uint8_t soffset = p * 8;

                for(size_t i = 0; i < 9; i++) {
                    with_parity[i + doffset] = bit_buffer_get_byte(rx_buffer, i + soffset) >> i;
                    if(i > 0) {
                        with_parity[i + doffset] |= bit_buffer_get_byte(rx_buffer, i + soffset - 1)
                                                    << (9 - i);
                    }

                    if(i > 0) {
                        bool val = bit_lib_get_bit(rx_parity, i - 1);
                        bit_lib_set_bit(with_parity + i, i - 1, val);
                    }
                }
            }

            for(size_t i = 0; i < length; i++) {
                bit_lib_reverse_bits(with_parity + i, 0, 8);
            }

            bit_buffer_copy_bytes(rx_buffer, with_parity, length);

            memset(display, 0, sizeof(display));
            for(uint8_t i = 0; i < length; i++) {
                snprintf(
                    display + (i * 2), sizeof(display), "%02x", bit_buffer_get_byte(rx_buffer, i));
            }
            FURI_LOG_D(
                TAG, "NFC Response with parity %d: %s [%02x]", length, display, rx_parity[0]);

        } else {
            FURI_LOG_W(TAG, "UNHANDLED FORMAT");
        }

        seader_send_nfc_rx(
            seader,
            (uint8_t*)bit_buffer_get_data(rx_buffer),
            bit_buffer_get_size_bytes(rx_buffer));

    } while(false);
    bit_buffer_free(tx_buffer);
    bit_buffer_free(rx_buffer);
}

void seader_parse_nfc_command_transmit(
    Seader* seader,
    NFCSend_t* nfcSend,
    SeaderPollerContainer* spc) {
    long timeOut = nfcSend->timeOut;
    Protocol_t protocol = nfcSend->protocol;
    FrameProtocol_t frameProtocol = protocol.buf[1];

#ifdef ASN1_DEBUG
    memset(display, 0, sizeof(display));
    for(uint8_t i = 0; i < nfcSend->data.size; i++) {
        snprintf(display + (i * 2), sizeof(display), "%02x", nfcSend->data.buf[i]);
    }

    FURI_LOG_D(
        TAG,
        "Transmit (%ld timeout) %d bytes [%s] via %lx",
        timeOut,
        nfcSend->data.size,
        display,
        frameProtocol);
#endif

    if(seader->credential->type == SeaderCredentialTypeVirtual) {
        seader_picopass_state_machine(seader, nfcSend->data.buf, nfcSend->data.size);
    } else if(frameProtocol == FrameProtocol_iclass) {
        seader_iso15693_transmit(
            seader, spc->picopass_poller, nfcSend->data.buf, nfcSend->data.size);
    } else if(frameProtocol == FrameProtocol_nfc) {
        if(spc->iso14443_4a_poller) {
            seader_iso14443a_transmit(
                seader,
                spc->iso14443_4a_poller,
                nfcSend->data.buf,
                nfcSend->data.size,
                (uint16_t)timeOut,
                nfcSend->format->buf);
        } else if(spc->mfc_poller) {
            seader_mfc_transmit(
                seader,
                spc->mfc_poller,
                nfcSend->data.buf,
                nfcSend->data.size,
                (uint16_t)timeOut,
                nfcSend->format->buf);
        }
    } else {
        FURI_LOG_W(TAG, "unknown frame protocol %lx", frameProtocol);
    }
}

void seader_parse_nfc_off(Seader* seader) {
    FURI_LOG_D(TAG, "Set Field Off");
    NFCResponse_t* nfcResponse = 0;
    nfcResponse = calloc(1, sizeof *nfcResponse);
    assert(nfcResponse);

    nfcResponse->present = NFCResponse_PR_nfcAck;

    Response_t* response = 0;
    response = calloc(1, sizeof *response);
    assert(response);

    response->present = Response_PR_nfcResponse;
    response->choice.nfcResponse = *nfcResponse;

    seader_send_response(seader, response, ExternalApplicationA, SAMInterface, 0);

    free(response);
    free(nfcResponse);
}

void seader_parse_nfc_command(Seader* seader, NFCCommand_t* nfcCommand, SeaderPollerContainer* spc) {
    switch(nfcCommand->present) {
    case NFCCommand_PR_nfcSend:
        seader_parse_nfc_command_transmit(seader, &nfcCommand->choice.nfcSend, spc);
        break;
    case NFCCommand_PR_nfcOff:
        seader_parse_nfc_off(seader);
        seader->worker->stage = SeaderPollerEventTypeComplete;
        break;
    default:
        FURI_LOG_W(TAG, "unparsed NFCCommand");
        break;
    };
}

bool seader_worker_state_machine(
    Seader* seader,
    Payload_t* payload,
    bool online,
    SeaderPollerContainer* spc) {
    bool processed = false;

    switch(payload->present) {
    case Payload_PR_response:
        FURI_LOG_D(TAG, "Payload_PR_response");
        seader_parse_response(seader, &payload->choice.response);
        processed = true;
        break;
    case Payload_PR_nfcCommand:
        FURI_LOG_D(TAG, "Payload_PR_nfcCommand");
        if(online) {
            seader_parse_nfc_command(seader, &payload->choice.nfcCommand, spc);
            processed = true;
        }
        break;
    case Payload_PR_errorResponse:
        FURI_LOG_W(TAG, "Payload_PR_errorResponse");
        processed = true;
        view_dispatcher_send_custom_event(seader->view_dispatcher, SeaderCustomEventWorkerExit);
        break;
    default:
        FURI_LOG_W(TAG, "unhandled payload");
        break;
    };

    return processed;
}

bool seader_process_success_response_i(
    Seader* seader,
    uint8_t* apdu,
    size_t len,
    bool online,
    SeaderPollerContainer* spc) {
    Payload_t* payload = 0;
    payload = calloc(1, sizeof *payload);
    assert(payload);
    bool processed = false;

    asn_dec_rval_t rval =
        asn_decode(0, ATS_DER, &asn_DEF_Payload, (void**)&payload, apdu + 6, len - 6);
    if(rval.code == RC_OK) {
#ifdef ASN1_DEBUG
        if(online == false) {
            memset(display, 0, sizeof(display));
            for(uint8_t i = 0; i < len - 6; i++) {
                snprintf(display + (i * 2), sizeof(display), "%02x", apdu[i + 6]);
            }
            FURI_LOG_D(TAG, "incoming APDU %s", display);

            char payloadDebug[384] = {0};
            memset(payloadDebug, 0, sizeof(payloadDebug));
            (&asn_DEF_Payload)
                ->op->print_struct(
                    &asn_DEF_Payload, payload, 1, seader_print_struct_callback, payloadDebug);
            if(strlen(payloadDebug) > 0) {
                FURI_LOG_D(TAG, "Received Payload: %s", payloadDebug);
            } else {
                FURI_LOG_D(TAG, "Received empty Payload");
            }
        } else {
            FURI_LOG_D(TAG, "Online mode");
        }
#endif

        processed = seader_worker_state_machine(seader, payload, online, spc);
    } else {
        memset(display, 0, sizeof(display));
        for(uint8_t i = 0; i < len; i++) {
            snprintf(display + (i * 2), sizeof(display), "%02x", apdu[i]);
        }
        FURI_LOG_D(TAG, "Failed to decode APDU payload: [%s]", display);
    }

    ASN_STRUCT_FREE(asn_DEF_Payload, payload);
    return processed;
}

bool seader_mf_df_check_card_type(uint8_t ATQA0, uint8_t ATQA1, uint8_t SAK) {
    return ATQA0 == 0x44 && ATQA1 == 0x03 && SAK == 0x20;
}

NfcCommand seader_worker_card_detect(
    Seader* seader,
    uint8_t sak,
    uint8_t* atqa,
    const uint8_t* uid,
    uint8_t uid_len,
    uint8_t* ats,
    uint8_t ats_len) {
    UNUSED(ats);
    UNUSED(ats_len);

    SeaderCredential* credential = seader->credential;

    CardDetails_t* cardDetails = 0;
    cardDetails = calloc(1, sizeof *cardDetails);
    assert(cardDetails);

    OCTET_STRING_fromBuf(&cardDetails->csn, (const char*)uid, uid_len);
    OCTET_STRING_t sak_string = {.buf = &sak, .size = 1};
    OCTET_STRING_t atqa_string = {.buf = atqa, .size = 2};
    uint8_t protocol_bytes[] = {0x00, 0x00};

    if(sak != 0 && atqa != NULL) { // type 4
        protocol_bytes[1] = FrameProtocol_nfc;
        OCTET_STRING_fromBuf(
            &cardDetails->protocol, (const char*)protocol_bytes, sizeof(protocol_bytes));
        cardDetails->sak = &sak_string;
        cardDetails->atqa = &atqa_string;
        credential->isDesfire = seader_mf_df_check_card_type(atqa[0], atqa[1], sak);
        if(credential->isDesfire) {
            memcpy(credential->diversifier, uid, uid_len);
            credential->diversifier_len = uid_len;
        }
    } else if(sak != 0 && atqa == NULL) { // MFC
        protocol_bytes[1] = FrameProtocol_nfc;
        OCTET_STRING_fromBuf(
            &cardDetails->protocol, (const char*)protocol_bytes, sizeof(protocol_bytes));
        cardDetails->sak = &sak_string;
    } else if(uid_len == 8) { // picopass
        protocol_bytes[1] = FrameProtocol_iclass;
        OCTET_STRING_fromBuf(
            &cardDetails->protocol, (const char*)protocol_bytes, sizeof(protocol_bytes));
        memcpy(credential->diversifier, uid, uid_len);
        credential->diversifier_len = uid_len;
        credential->isDesfire = false;
    } else {
        FURI_LOG_D(TAG, "Unknown card type");
    }

    seader_send_card_detected(seader, cardDetails);
    // Print version information for app and firmware for later review in log
    const Version* version = version_get();
    FURI_LOG_I(
        TAG,
        "Firmware origin: %s firmware version: %s app version: %s",
        version_get_firmware_origin(version),
        version_get_version(version),
        FAP_VERSION);

    free(cardDetails);
    return NfcCommandContinue;
}
