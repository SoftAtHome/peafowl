/*
 * demo_identification.c
 *
 * Given a .pcap file, it identifies the protocol of all the packets contained in it.
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <peafowl/peafowl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char *pcap_filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char *packet;
  uint32_t protocols[PFWL_PROTO_L7_NUM];
  struct pcap_pkthdr header;
  memset(protocols, 0, sizeof(protocols));
  uint32_t unknown = 0;

  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  pfwl_string_t version;
  pfwl_string_t sni;
  pfwl_string_t uaid;
  pfwl_string_t ja3;
  pfwl_string_t joy;
  pfwl_string_t npf;
  pfwl_string_t	token;
  int first_packet = 1;

  pfwl_state_t *state = pfwl_init();

  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_VERSION);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_SNI);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_UAID);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_JA3);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_JOY);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_NPF);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_TOKEN);

  pfwl_dissection_info_t r;
  pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
  while ((packet = pcap_next(handle, &header)) != NULL) {
    if (pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK) {
      if (r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP) {
        if (r.l7.protocol < PFWL_PROTO_L7_NUM) {
          ++protocols[r.l7.protocol];
          if (first_packet && (!strcmp("QUIC5", pfwl_get_L7_protocol_name(r.l7.protocol)))) {
            int res, res1, res2, res3, res4, res5, res6;
            res = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, &version);
            res1 = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, &sni);
            res2 = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, &uaid);
            res3 = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JA3, &ja3);
            res4 = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JOY, &joy);
            res5 = pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_NPF, &npf);
						res6	= pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_TOKEN, &token);
            printf("RES %d %d %d %d %d %d %d\n", res, res1, res2, res3, res4, res5, res6);
            if (!res) {
              printf("Quic Version: %.*s\n", (int) version.length, version.value);
            } else {
              printf("Quic Version: unknown\n");
            }

            if (!res1) {
              printf("Quic SNI: %.*s\n", (int) sni.length, sni.value);
            } else {
              printf("Quic SNI: unknown\n");
            }

            if (!res2) {
              printf("Quic UAID: %.*s\n", (int) uaid.length, uaid.value);
            } else {
              printf("Quic UAID: unknown\n");
            }

            if (!res3) {
              printf("Quic JA3 fingerprint: ");
              size_t i;
              for (i = 0; i < ja3.length; i++) {
                printf("%c", ja3.value[i]);
              }
              printf("\n");
            } else {
              printf("Quic JA3: unknown\n");
            }

            if (!res4) {
              printf("Quic Joy fingerprint: ");
              size_t i;
              for (i = 0; i < joy.length; i++) {
                printf("%c", joy.value[i]);
              }
              printf("\n");
            } else {
              printf("Quic Joy fingerprint: unknown\n");
            }

            if (!res5) {
              printf("Quic NPF fingerprint: ");
              size_t i;
              for (i = 0; i < npf.length; i++) {
                printf("%c", npf.value[i]);
              }
              printf("\n");
            } else {
              printf("Quic NPF fingerprint: unknown\n");
            }

            if (!res6) {
              printf("Quic Token: ");
              size_t i;
              for (i = 0; i < token.length; i++) {
                printf("%c", token.value[i]);
              }
              printf("\n");
            } else {
              printf("Quic Token: unknown\n");
            }
            first_packet = 0;
          }
        } else {
          ++unknown;
        }
      } else {
        ++unknown;
      }
    }
  }
  pfwl_terminate(state);

  if (unknown > 0)
    printf("Unknown packets: %" PRIu32 "\n", unknown);
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    if (protocols[i] > 0) {
      printf("%s packets: %" PRIu32 "\n", pfwl_get_L7_protocol_name(i), protocols[i]);
    }
  }
  pcap_close(handle);
  return 0;
}
