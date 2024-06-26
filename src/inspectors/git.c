/*
 * git.c
 *
 * This protocol inspector is adapted from
 * the nDPI Git dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/git.c)
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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

uint8_t check_git(pfwl_state_t *state, const unsigned char *app_data, size_t data_length,
                  pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
  (void) state;
  (void) flow_info_private;

  if (data_length > 4 && (pkt_info->l4.port_src == port_git || pkt_info->l4.port_dst == port_git)) {
    uint8_t found_git = 1;
    uint16_t offset = 0;

    while ((offset + 4u) < data_length) {
      char len[5];
      uint32_t git_pkt_len;
      memcpy(&len, &app_data[offset], 4);
      len[4] = 0;
      git_pkt_len = atoi(len);

      if ((data_length < git_pkt_len) || (git_pkt_len == 0 /* Bad */)) {
        found_git = 0;
        break;
      } else {
        offset += git_pkt_len;
        data_length -= git_pkt_len;
      }
    }

    if (found_git) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
