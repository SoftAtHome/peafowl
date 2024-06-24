/*
 * quic_tls_fingerprinting.h
 *
 * TLS 1.3 fingerprinting
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

/* JA3 Fingerprinting */
void ja3_parse_supported_groups(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *ja3_supgrps_string, size_t *ja3_supgrps_string_len);
void ja3_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *ja3_string, size_t *ja3_string_len, unsigned char *ja3_supgrps_string, size_t *ja3_supgrps_string_len);
size_t parse_ja3_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *ja3_string, uint16_t tls_version);

/* Joy Fingerprinting */
void joy_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *joy_string, size_t *joy_string_len);
size_t parse_joy_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *joy_string, uint16_t tls_version);

/* NPF Fingerprinting */
void npf_qtp(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *extensions, size_t *extensions_len);
void npf_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *npf_string, size_t *npf_string_len, uint16_t ext_len);
size_t parse_npf_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *npf_string, uint16_t tls_version, uint16_t quic_version);

size_t parse_ja3_hash(pfwl_state_t *state, unsigned char *ja3_string, size_t ja3_string_len, char *ja3_start);
char* parse_joy_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *joy_string, size_t *joy_string_len);
char* parse_npf_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *npf_string, size_t *npf_string_len);
