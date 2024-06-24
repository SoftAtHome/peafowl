//Brecht vorige
/*
 * quic_tls13.c
 *
 * TLS 1.3 record layer decoder for newer quic versions
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2020 SoftAtHome (david.cluytens@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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

#ifdef HAVE_OPENSSL

#include "quic_ssl_utils.h"
#include "quic_tls13.h"
#include "quic_tls_fingerprinting.h"
#include "quic_utils.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdbool.h>

#define MAX_EC 512
#define MAX_ECPF 512

/*
 *	 GREASE_TABLE Ref:
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-00
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-01
 *    - https://datatracker.ietf.org/doc/html/rfc8701
 *
 * 	switch grease-table is much faster than looping and testing a lookup grease table
 *
 */
static unsigned int is_grease(uint32_t x) {
  switch (x) {
  case 0x0a0a:
  case 0x1a1a:
  case 0x2a2a:
  case 0x3a3a:
  case 0x4a4a:
  case 0x5a5a:
  case 0x6a6a:
  case 0x7a7a:
  case 0x8a8a:
  case 0x9a9a:
  case 0xaaaa:
  case 0xbaba:
  case 0xcaca:
  case 0xdada:
  case 0xeaea:
  case 0xfafa:
    return 1;
  default:
    return 0;
  }
  return 0;
}

void tls13_parse_google_user_agent(pfwl_state_t *state, const unsigned char *data, size_t len,
                                   pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
  (void) flow_info_private;

  char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
  memcpy(scratchpad, data, len);
  pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, (const unsigned char *) scratchpad,
                        len);
  state->scratchpad_next_byte += len;
}

void tls13_parse_quic_transport_params(pfwl_state_t *state, const unsigned char *data, size_t len,
                                       pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
  size_t pointer = 0;
  size_t TLVlen = 0;
  for (pointer = 0; pointer < len; pointer += TLVlen) {
    uint64_t TLVtype = 0;
    pointer += quic_get_variable_len(data, pointer, &TLVtype);
    TLVlen = data[pointer];
    pointer++;
    // printf("parameter TLV %08X TLV Size %02d\n", TLVtype, TLVlen);
    switch (TLVtype) {
    case 0x3129:
      if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) {
        tls13_parse_google_user_agent(state, data + pointer, TLVlen, pkt_info, flow_info_private);
      }
    default:
      break;
    }
  }
}

// TODO: use this len param
void tls13_parse_servername(pfwl_state_t *state, const unsigned char *data, size_t len,
                            pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
  (void) len;
  (void) flow_info_private;

  size_t pointer = 0;
  // uint16_t 	list_len = ntohs(*(uint16_t *)(data));
  // size_t 		type 	= data[2];
  uint16_t server_len = ntohs(get_u16(data, 3));
  pointer = 2 + 1 + 2;

  char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
  memcpy(scratchpad, data + pointer, server_len);
  pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, (const unsigned char *) scratchpad,
                        server_len);
  state->scratchpad_next_byte += server_len;
}

// Elliptical curves extension renamed to supported groups in TLS 1.3
static void parse_ec(const unsigned char *data, const unsigned char *data_end, uint16_t *ec, unsigned int *nbr_ec) {
  // skip len
  data += 2;
  while (data + 1 < data_end && (*nbr_ec < MAX_EC)) {
    uint16_t ec_value = ntohs(get_u16(data, 0));
    ec[*nbr_ec] = ec_value;
    (*nbr_ec)++;
    data += 2;
  }
}

static void parse_ecpf(const unsigned char *data, const unsigned char *data_end, uint8_t *ecpf,
                       unsigned int *nbr_ecpf) {
  // skip len
  data += 1;
  while (data < data_end && (*nbr_ecpf < MAX_ECPF)) {
    uint8_t ecpf_value = *data;
    ecpf[*nbr_ecpf] = ecpf_value;
    (*nbr_ecpf)++;
    data += 1;
  }
}

// TODO: mag weg
void tls13_parse_supported_groups(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *ja3_supgrps_string, size_t *ja3_supgrps_string_len) {
	size_t		pointer = 0;
	size_t 		TLVlen 	= 0;

	size_t grps_len = ntohs(*(uint16_t *)(&data[pointer]));
	pointer += 2;

	for (pointer; pointer < grps_len+2; pointer += 2) {
		size_t		supgrp = 0;
		supgrp = ntohs(*(uint16_t *)(&data[pointer]));
	 	*ja3_supgrps_string_len += sprintf(ja3_supgrps_string + *ja3_supgrps_string_len, "%u-", supgrp);
	}
}

void tls13_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len,
                            pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
                            char *ja3_string, size_t *ja3_string_len) {
  size_t pointer;
  size_t TLVlen;

  // list of ext10, ext11 for ja3
  uint16_t ec[MAX_EC];
  uint8_t ecpf[MAX_ECPF];

  unsigned int nbr_ec = 0;
  unsigned int nbr_ecpf = 0;

  for (pointer = 0; pointer < len; pointer += TLVlen) {
    uint16_t TLVtype = ntohs(get_u16(data, pointer));
    pointer += 2;
    TLVlen = ntohs(get_u16(data, pointer));
    pointer += 2;
    // printf("TLV %02d TLV Size %02d\n", TLVtype, TLVlen);

    switch (TLVtype) {
    /* skip grease values */
    case 0x0a0a:
    case 0x1a1a:
    case 0x2a2a:
    case 0x3a3a:
    case 0x4a4a:
    case 0x5a5a:
    case 0x6a6a:
    case 0x7a7a:
    case 0x8a8a:
    case 0x9a9a:
    case 0xaaaa:
    case 0xbaba:
    case 0xcaca:
    case 0xdada:
    case 0xeaea:
    case 0xfafa:
      /* Grease values must be ignored */
      continue;
      break;

      /* Server Name */
    case 0:
      if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)) {
        tls13_parse_servername(state, data + pointer, TLVlen, pkt_info, flow_info_private);
      }
      break;
      /* Extension quic transport parameters */
    case 10:
      parse_ec(&data[pointer], &data[pointer + TLVlen], ec, &nbr_ec);
      break;
    case 11:
      parse_ecpf(&data[pointer], &data[pointer + TLVlen], ecpf, &nbr_ecpf);
      break;
    case 65445:
      tls13_parse_quic_transport_params(state, data + pointer, TLVlen, pkt_info, flow_info_private);
      break;
    default:
      break;
    }
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", TLVtype);
  }
  if (len) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }

  // add ext10
  *ja3_string_len += sprintf(ja3_string + *ja3_string_len, ",");
  for (unsigned int i = 0; i < nbr_ec; ++i) {
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", ec[i]);
  }
  if (nbr_ec) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }

  // add ext11
  *ja3_string_len += sprintf(ja3_string + *ja3_string_len, ",");
  for (unsigned int i = 0; i < nbr_ecpf; ++i) {
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", ecpf[i]);
  }
  if (nbr_ecpf) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }
  ja3_string[*ja3_string_len] = '\0';
}

// return the actual size of the encoded value
// return zero in case of failure
static uint8_t parse_len(const unsigned char *tls_data, const unsigned char *tls_data_end, uint64_t *value) {
  // size check for the length of the encoded value

  if (&tls_data[0] >= tls_data_end)
    return 0;
  uint8_t len_val = quic_length_of_encoded_value(tls_data[0]);
  if (&tls_data[len_val - 1] >= tls_data_end)
    return 0;

  // can safely read actual value now
  len_val = quic_get_variable_len(tls_data, 0, value);
  return len_val;
}

static size_t compute_bit_buffer_size(size_t tls_data_length) {
  size_t size = tls_data_length / 8;
  if (tls_data_length % 8 != 0)
    ++size;

  return size;
}

typedef struct {
  unsigned char *buffer;
  unsigned char *bit_buffer;
  size_t size;
  int done;
} reassembled_state_t;

static bool reassembled_state_ctor(reassembled_state_t *reassembled_state, size_t tls_data_length) {
  reassembled_state->done = 0;
  reassembled_state->buffer = calloc(1, tls_data_length);
  reassembled_state->bit_buffer = calloc(1, compute_bit_buffer_size(tls_data_length));
  if (!reassembled_state->buffer || !reassembled_state->bit_buffer) {
    printf("calloc failed\n");
    free(reassembled_state->buffer);
    free(reassembled_state->bit_buffer);
    return false;
  }
  reassembled_state->size = tls_data_length;
  return true;
}

static void reassembled_state_dtor(reassembled_state_t *reassembled_state) {
  free(reassembled_state->buffer);
  free(reassembled_state->bit_buffer);
}

static void reassembled_state_validate(reassembled_state_t *reassembled_state) {
  if ((reassembled_state->bit_buffer[0] & 0xF) == 0xF) {
    bool at_least_one_byte_missing = false;
    const unsigned char *b = reassembled_state->buffer;
    uint32_t msg_len = (b[1] << 16) + (b[2] << 8) + b[3];
    for (size_t i = 4; i < msg_len + 4; ++i) {
      size_t bit_idx = i / 8;
      unsigned char bit_mask = 1 << i % 8;

      if ((reassembled_state->bit_buffer[bit_idx] & bit_mask) == 0) {
        at_least_one_byte_missing = true;
        break;
      }
    }
    if (!at_least_one_byte_missing)
      reassembled_state->done = 1;
  }
}

// range must be valid
static void reassembled_state_update_bit_buffer(reassembled_state_t *reassembled_state, size_t to_offset,
                                                uint64_t length) {
  for (size_t i = to_offset; i < to_offset + length; ++i) {
    size_t bit_idx = i / 8;
    unsigned char bit_mask = 1 << i % 8;
    reassembled_state->bit_buffer[bit_idx] |= bit_mask;
  }
}

static bool reassembled_state_add_data(reassembled_state_t *reassembled_state, size_t to_offset,
                                       const unsigned char *from, uint64_t length) {
  // check fits into buffer
  if (to_offset + length > reassembled_state->size)
    return false;

  memcpy(&reassembled_state->buffer[to_offset], from, length);
  reassembled_state_update_bit_buffer(reassembled_state, to_offset, length);
  reassembled_state_validate(reassembled_state);

  return true;
}

static size_t handle_frame_00(const unsigned char *tls_data, const unsigned char *tls_data_end,
                              reassembled_state_t *reassembled_state) {
  (void) tls_data;
  (void) tls_data_end;
  (void) reassembled_state;
  /* frame 00 is padding, skip it */
  return 1;
}

static size_t handle_frame_01(const unsigned char *tls_data, const unsigned char *tls_data_end,
                              reassembled_state_t *reassembled_state) {
  (void) tls_data;
  (void) tls_data_end;
  (void) reassembled_state;
  /* frame 01 is ping, skip it */
  return 1;
}

static size_t handle_frame_06(const unsigned char *tls_data, const unsigned char *tls_data_end,
                              reassembled_state_t *reassembled_state) {
  /* frame 06 is tls thingy, copy the actual content */
  uint64_t offset;
  uint8_t off_size = parse_len(&tls_data[1], tls_data_end, &offset);
  if (off_size == 0)
    return 0;
  uint64_t length;
  uint8_t length_size = parse_len(&tls_data[1 + off_size], tls_data_end, &length);
  if (length_size == 0)
    return 0;

  if (&tls_data[1 + off_size + length_size + length - 1] >= tls_data_end)
    return 0;

  if (!reassembled_state_add_data(reassembled_state, offset, &tls_data[1 + off_size + length_size], length))
    return 0;

  return 1 + off_size + length_size + length;
}

uint8_t check_tls13(pfwl_state_t *state, const unsigned char *tls_data, size_t tls_data_length,
                    pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, uint32_t quic_version) {
	size_t tls_pointer = 0;
  uint8_t retval = PFWL_PROTOCOL_NO_MATCHES;

  reassembled_state_t reassembled_state;

  if (!reassembled_state_ctor(&reassembled_state, tls_data_length)) {
    goto end_exit;
  }

  while (tls_pointer < tls_data_length) {
    unsigned char tls_record_frame_type = tls_data[tls_pointer];
    
    size_t frame_size;
    switch (tls_record_frame_type) {
    case 0x00:
      frame_size = handle_frame_00(&tls_data[tls_pointer], &tls_data[tls_data_length], &reassembled_state);
      break;
    case 0x01:
      frame_size = handle_frame_01(&tls_data[tls_pointer], &tls_data[tls_data_length], &reassembled_state);
      break;
    case 0x06:
    /* in gquic, the crypto frame is 8 */
    case 0x08:
      frame_size = handle_frame_06(&tls_data[tls_pointer], &tls_data[tls_data_length], &reassembled_state);
      break;
    default:
      printf("Unknown frame type %d\n", tls_record_frame_type);
      goto end;
      break;
    }
    if (frame_size == 0) {
      printf("Parsing frame failed\n");
      goto end;
    }
    tls_pointer += frame_size;
  }

  if (!reassembled_state.done)
    goto end;

  const unsigned char *proper_tls_data = reassembled_state.buffer;
  tls_pointer = 0;

	/* Parse TLS Handshake protocol */
  size_t handshake_type = proper_tls_data[tls_pointer];
  tls_pointer++;

  // size_t 	length = (proper_tls_data[tls_pointer] << 16) + (proper_tls_data[tls_pointer+1] << 8) +
  // proper_tls_data[tls_pointer+2];
  tls_pointer += 3;

  uint16_t tls_version = ntohs(*(uint16_t *) (&proper_tls_data[tls_pointer]));
  tls_pointer += 2;

	if (handshake_type == 1) { /* We only inspect client hello which has a type equal to 1 */	
		/* skipping random data 32 bytes */
		tls_pointer += 32;

		/* skipping legacy_session_id one byte */
		tls_pointer += 1;

    /* Fingerprinting */
    unsigned char ja3_string[1024];
    size_t ja3_string_len;
    char *ja3_hash;
    size_t ja3_hash_len;

	  unsigned char joy_string[1024];
	  size_t joy_string_len;

	  unsigned char npf_string[1024];
	  size_t npf_string_len;

		ja3_string_len = parse_ja3_string(state, proper_tls_data + tls_pointer, tls_data_length, pkt_info, flow_info_private,
                                      ja3_string, tls_version);
    //ja3_hash_len = parse_ja3_hash(state, ja3_string, ja3_string_len, ja3_hash);
    
    unsigned char md5[16];
    size_t md5sum_len = md5_digest_message((const unsigned char *) ja3_string, ja3_string_len, md5);

    char *ja3_start = state->scratchpad + state->scratchpad_next_byte;

    for (size_t n = 0; n < md5sum_len; n++) {
      sprintf(state->scratchpad + state->scratchpad_next_byte, "%02x", md5[n]);
      state->scratchpad_next_byte += 2;
    }

    // printf("JA3 md5 %s\n", ja3_start);

    if (ja3_string_len == 0) {
      printf("JA3 Fingerprint failed");
    } else {
      pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JA3, (const unsigned char *) ja3_start,
                            md5sum_len*2);
    }
		joy_string_len = parse_joy_string(state, proper_tls_data + tls_pointer, tls_data_length, pkt_info, flow_info_private,
                                      joy_string, tls_version);
    if (joy_string_len == 0) {
      printf("Joy Fingerprint failed");
    } else {
      pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JOY, joy_string, joy_string_len);
    }
		npf_string_len = parse_npf_string(state, proper_tls_data + tls_pointer, tls_data_length, pkt_info, flow_info_private,
                                      npf_string, tls_version, quic_version);
    if (npf_string_len == 0) {
      printf("NPF Fingerprint failed");
    } else {
      pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_NPF, npf_string, npf_string_len);
    }
    
		// /* Cipher suites and length */
    // uint16_t cipher_suite_len = ntohs(get_u16(proper_tls_data, tls_pointer));
    // tls_pointer += 2;

    // for (size_t i = 0; i < cipher_suite_len; i += 2) {
    //   uint16_t cipher_suite = ntohs(get_u16(proper_tls_data, tls_pointer + i));
    //   if (is_grease(cipher_suite)) {
    //     continue; // skip grease value
    //   }
    // }
    // tls_pointer += cipher_suite_len;

		// /* compression methods length */
    // size_t compression_methods_len = proper_tls_data[tls_pointer];
    // tls_pointer++;

		// /* Skip compression methods */
    // tls_pointer += compression_methods_len;

		// /* Extension length */
    // uint16_t ext_len = ntohs(get_u16(proper_tls_data, tls_pointer));
    // tls_pointer += 2;

		// /* Add Extension length to the ja3 string */
    // unsigned const char *ext_data = proper_tls_data + tls_pointer;

    // /* lets iterate over the exention list */
    // tls13_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, ja3_string, &ja3_string_len);
	}
  if (reassembled_state.done)
    retval = PFWL_PROTOCOL_MATCHES;

end:
 reassembled_state_dtor(&reassembled_state);

end_exit:

	return retval;
}

#else
uint8_t check_tls13(pfwl_state_t *state, const unsigned char *app_data, size_t data_length,
                    pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
  (void) state;
  (void) app_data;
  (void) data_length;
  (void) pkt_info;
  (void) flow_info_private;

  return PFWL_PROTOCOL_NO_MATCHES;
}
#endif