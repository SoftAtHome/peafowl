/**
 * rtp.c
 *
 * Created on: 29/06/2016
 *
 * =========================================================================
 *  Copyright (C) 2012-2019, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
 *  Copyright (C) 2018, Michele Campus (michelecampus5@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to
 * do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_RTP 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
  if (PFWL_DEBUG_RTP)                                                        \
  fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

#define SIZE 24
typedef enum {
  G_711_U_Law = 0,
  GSM_6_10 = 3,
  G_723_1 = 4,
  G_711_A_Law = 8,
  G_722 = 9,
  Comfort_Noise = 13,
  G_729 = 18,
  H_263 = 34,
  Dynamic_RTP = 96,
  RADP = 97,
  DTMF = 101,
  SILK_Narrow = 103,
  SILK_Wide = 104,
  Siren = 111,
  G_722_1 = 112,
  RT_Audio_Wide = 114,
  RT_Audio_Narrow = 115,
  G_726 = 116,
  G_722b = 117,
  Comfort_Noise_Wide = 118,
  RT_Video = 121,
  H_264 = 122,
  H_264_FEC = 123,
  X_data = 127,
} RTPpayloadType;

/* typedef enum { */
/*     RTCP_SENDER    = 200, */
/*     RTCP_RECEIVER  = 201, */
/*     RTCP_SRC_DESCR = 202, */
/*     RTCP_BYE       = 203, */
/* }RTCPpayloadType; */

struct rtp_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  // 2 bytes
  uint8_t CC : 4;
  uint8_t extension : 1;
  uint8_t padding : 1;
  uint8_t version : 2;
  // 1 byte
  uint8_t pType : 7;
  uint8_t marker : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
  // 2 bytes
  uint8_t version : 2;
  uint8_t padding : 1;
  uint8_t extension : 1;
  uint8_t CC : 4;
  // 1 byte
  uint8_t marker : 1;
  uint8_t pType : 7;
#else
#endif
  uint16_t seq_num;
  uint32_t timestamp;
  uint32_t SSRC;
} __attribute__((packed));

static int8_t is_valid_payload_type(uint8_t PT) {
  switch (PT) {
  case G_711_U_Law:
  case GSM_6_10:
  case G_723_1:
  case G_711_A_Law:
  case G_722:
  case Comfort_Noise:
  case G_729:
  case H_263:
  case Dynamic_RTP:
  case RADP:
  case DTMF:
  case SILK_Narrow:
  case SILK_Wide:
  case Siren:
  case G_722_1:
  case RT_Audio_Wide:
  case RT_Audio_Narrow:
  case G_726:
  case G_722b:
  case Comfort_Noise_Wide:
  case RT_Video:
  case H_264:
  case H_264_FEC:
  case X_data:
    return PT;
  default:
    return -1;
  }
}

uint8_t check_rtp(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  pfwl_dissector_accuracy_t accuracy =
      state->inspectors_accuracy[PFWL_PROTO_L7_RTP];

  if (data_length < 2 || ntohs(pkt_info->l4.port_dst) <= 1024 ||
      ntohs(pkt_info->l4.port_src) <= 1024) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  if (data_length >= 12) {
    if ((app_data[0] & 0xFF) == 0x80 ||
        (app_data[0] & 0xFF) == 0xA0) { /* RTP magic byte[1] */
      int8_t pType = 0;
      struct rtp_header *rtp = (struct rtp_header *) app_data;

      if(rtp->version == 2) { // check Version
        if(rtp->marker == 0 || rtp->marker == 1) { // check Marker
          pType = is_valid_payload_type(rtp->pType); // check Payload Type
          if(pType != -1) {
            if(accuracy == PFWL_DISSECTOR_ACCURACY_HIGH) {
              pfwl_field_t* extracted_fields = pkt_info->l7.protocol_fields;

              if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_RTP_PTYPE)){
                pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTP_PTYPE,
                                      (int64_t) pType);
              }
              if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_RTP_SEQNUM)){
                pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTP_SEQNUM,
                                      (int64_t) ntohs(rtp->seq_num));
              }
              if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_RTP_TIMESTP)){
                pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTP_TIMESTP,
                                      (int64_t) ntohl(rtp->timestamp));
              }
              if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_RTP_SSRC)){
                pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTP_SSRC,
                                      (int64_t) ntohl(rtp->SSRC));
              }
              return PFWL_PROTOCOL_MATCHES;
            }else{
              return PFWL_PROTOCOL_MATCHES;
            }
          }else{
            return PFWL_PROTOCOL_NO_MATCHES;
          }
        }
      }
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
