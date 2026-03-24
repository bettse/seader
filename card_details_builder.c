#include "card_details_builder.h"

#include <string.h>

#include <FrameProtocol.h>

bool seader_card_details_build(
    CardDetails_t* card_details,
    uint8_t sak,
    const uint8_t* uid,
    uint8_t uid_len,
    const uint8_t* ats,
    uint8_t ats_len) {
    if(!card_details || !uid || uid_len == 0U) {
        return false;
    }

    memset(card_details, 0, sizeof(*card_details));

    if(OCTET_STRING_fromBuf(&card_details->csn, (const char*)uid, uid_len) != 0) {
        return false;
    }

    uint8_t protocol_bytes[] = {0x00, 0x00};
    if(ats != NULL) {
        protocol_bytes[1] = FrameProtocol_nfc;
        if(OCTET_STRING_fromBuf(
               &card_details->protocol,
               (const char*)protocol_bytes,
               sizeof(protocol_bytes)) != 0) {
            seader_card_details_reset(card_details);
            return false;
        }
        card_details->sak = calloc(1, sizeof(*card_details->sak));
        card_details->atsOrAtqbOrAtr = calloc(1, sizeof(*card_details->atsOrAtqbOrAtr));
        if(!card_details->sak || !card_details->atsOrAtqbOrAtr ||
           OCTET_STRING_fromBuf(card_details->sak, (const char*)&sak, 1) != 0 ||
           OCTET_STRING_fromBuf(card_details->atsOrAtqbOrAtr, (const char*)ats, ats_len) != 0) {
            seader_card_details_reset(card_details);
            return false;
        }
    } else if(uid_len == 8U) {
        protocol_bytes[1] = FrameProtocol_iclass;
        if(OCTET_STRING_fromBuf(
               &card_details->protocol,
               (const char*)protocol_bytes,
               sizeof(protocol_bytes)) != 0) {
            seader_card_details_reset(card_details);
            return false;
        }
    } else {
        protocol_bytes[1] = FrameProtocol_nfc;
        if(OCTET_STRING_fromBuf(
               &card_details->protocol,
               (const char*)protocol_bytes,
               sizeof(protocol_bytes)) != 0) {
            seader_card_details_reset(card_details);
            return false;
        }
        card_details->sak = calloc(1, sizeof(*card_details->sak));
        if(!card_details->sak ||
           OCTET_STRING_fromBuf(card_details->sak, (const char*)&sak, 1) != 0) {
            seader_card_details_reset(card_details);
            return false;
        }
    }

    return true;
}

void seader_card_details_reset(CardDetails_t* card_details) {
    if(!card_details) {
        return;
    }

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_CardDetails, card_details);
    memset(card_details, 0, sizeof(*card_details));
}
