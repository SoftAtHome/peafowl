/*
 * ssl.c
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

#include <peafowl/external/md5.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#include <stdio.h>

#define SSL_BIDIRECTIONAL \
  0 // If set to 1, before confirming that the flow is SSL, we expect to see SSL header in both directions

typedef enum {
  TLS_invalid = 0,
  TLS_change_cipher_spec = 0x14,
  TLS_alert = 0x15,
  TLS_handshake = 0x16,
  TLS_application_data = 0x17,
  TLS_heartbeat = 0x18, /* RFC 6520 */

} pfwl_ssl_content_type_t;

#define PFWL_DEBUG_SSL 0
#define debug_print(fmt, ...)            \
  do {                                   \
    if (PFWL_DEBUG_SSL)                  \
      fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

#define PFWL_MAX_SSL_REQUEST_SIZE 10000

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

// GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
const uint32_t GREASE_TABLE[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                                 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

uint is_grease(uint32_t x) {
  size_t size = sizeof(GREASE_TABLE) / sizeof(GREASE_TABLE[0]);
  for (size_t i = 0; i < size; i++) {
    if (x == GREASE_TABLE[i]) {
      return 1;
    }
  }
  return 0;
}

typedef enum {
  HELLO_REQUEST = 0x00,
  CLIENT_HELLO = 0x01,
  SERVER_HELLO = 0x02,
  CERTIFICATE = 0x0b,
  SERVER_KEY_EXCHANGE = 0x0c,
  CERTIFICATE_REQUEST = 0x0d,
  SERVER_DONE = 0x0e,
  CERTIFICATE_VERIFY = 0x0f,
  CLIENT_KEY_EXCHANGE = 0x10,
  FINISHED = 0x14,
} handshake_msg_types;

/* Can't call libc functions from kernel space, define some stub instead */

#define pfwl_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define pfwl_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define pfwl_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define pfwl_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define pfwl_ispunct(ch)                                                                           \
  (((ch) >= '!' && (ch) <= '/') || ((ch) >= ':' && (ch) <= '@') || ((ch) >= '[' && (ch) <= '`') || \
   ((ch) >= '{' && (ch) <= '~'))

static int check_punycode_string(char *buffer, int len) {
  int i = 0;

  while (i++ < len) {
    if (buffer[i] == 'x' && buffer[i + 1] == 'n' && buffer[i + 2] == '-' && buffer[i + 3] == '-')
      // is a punycode string
      return 1;
  }
  // not a punycode string
  return 0;
}

static void stripCertificateTrailer(char *buffer, size_t *buffer_len) {

  size_t i;

  //  printf("->%s<-\n", buffer);

  for (i = 0; i < *buffer_len; i++) {
    // printf("%c [%d]\n", buffer[i], buffer[i]);

    if ((buffer[i] != '.') && (buffer[i] != '-') && (buffer[i] != '_') && (buffer[i] != '*') &&
        (!pfwl_isalpha(buffer[i])) && (!pfwl_isdigit(buffer[i]))) {
      buffer[i] = '\0';
      *buffer_len = i;
      break;
    }
  }

  /* check for punycode encoding */
  int is_puny = check_punycode_string(buffer, *buffer_len);

  // not a punycode string - need more checks
  if (is_puny == 0) {

    if (i > 0)
      i--;

    while (i > 0) {
      if (!pfwl_isalpha(buffer[i])) {
        buffer[i] = '\0';
        *buffer_len = i;
        i--;
      } else
        break;
    }

    for (i = *buffer_len; i > 0; i--) {
      if (buffer[i] == '.')
        break;
      else if (pfwl_isdigit(buffer[i])) {
        buffer[i] = '\0';
        *buffer_len = i;
      }
    }
  }
}

static void ssl_flow_cleaner(pfwl_flow_info_private_t *flow_info_private) {
  if (flow_info_private->ssl_information.ssl_data) {
    free(flow_info_private->ssl_information.ssl_data);
    flow_info_private->ssl_information.ssl_data = NULL;
  }
  if (flow_info_private->ssl_information.certificates) {
    free(flow_info_private->ssl_information.certificates);
    flow_info_private->ssl_information.certificates = NULL;
  }
}

static int processExtensions(pfwl_state_t *state, pfwl_flow_info_private_t *flow_info_private, int offset,
                             const unsigned char *payload, uint16_t extensions_len, uint extension_offset,
                             size_t data_length, char *buffer, size_t buffer_len, pfwl_field_t *fields,
                             uint32_t *next_server_extension, uint32_t *remaining_extension_len,
                             size_t scratchpad_start, uint8_t handshake_msg_type) {
  char *extensions = state->scratchpad + state->scratchpad_next_byte;
  size_t ja3_last_byte = 0;
  size_t extensions_next_char = 0;
  size_t ellcurves_offset = 0;
  size_t ellpoints_offset = 0;
  uint8_t ellcurves_present = 0;
  uint8_t ellpoints_present = 0;
  char *server_name = NULL;
  uint32_t server_name_length = 0;

  while (extension_offset < extensions_len) {
    if (offset + extension_offset > data_length) {
      *next_server_extension = offset + extension_offset - data_length;
      *remaining_extension_len = extensions_len - extension_offset;
      goto end;
    }
    u_int16_t extension_id, extension_len;

    if (offset + extension_offset + 1 >= data_length) {
      goto end;
    }
    extension_id = ntohs(get_u16(payload, offset + extension_offset));
    extension_offset += 2;

    if (offset + extension_offset + 1 >= data_length) {
      goto end;
    }
    extension_len = ntohs(get_u16(payload, offset + extension_offset));
    extension_offset += 2;

    debug_print("SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);

    if ((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS) ||
         pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) &&
        !is_grease(extension_id)) {
      extensions_next_char += sprintf(extensions + extensions_next_char, "%d-", extension_id);
    }

    // TODO Check that offset + extension_offset + extension_len < data_length
    if (extension_id == 0) {
      u_int begin = 0, len;
      server_name = (char *) &payload[offset + extension_offset];

      if (offset + extension_offset + extension_len >= data_length) {
        goto end;
      }

      while (begin < extension_len) {
        if ((!pfwl_isprint(server_name[begin])) || pfwl_ispunct(server_name[begin]) || pfwl_isspace(server_name[begin]))
          begin++;
        else
          break;
      }

      server_name += begin;

      len = buffer_len ? MIN(extension_len - begin, buffer_len - 1) : 0;
      strncpy(buffer, server_name, len);
      buffer[len] = '\0';
      stripCertificateTrailer(buffer, &buffer_len);
      debug_print("SNI: %s\n", buffer);
      server_name_length = buffer_len;

    } else if (extension_id == 10 && extension_len > 2) {
      // Elliptic curves
      ellcurves_present = 1;
      ellcurves_offset = extension_offset;
    } else if (extension_id == 11 && extension_len >= 2) {
      // EllipticCurvePointFormat
      ellpoints_present = 1;
      ellpoints_offset = extension_offset;
    }

    extension_offset += extension_len;
  }
  // Set extensions
  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS) ||
      pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) {
    // Remove last dash
    if (extensions_next_char) {
      extensions_next_char -= 1;
    }
    sprintf(extensions + extensions_next_char, ",");
    state->scratchpad_next_byte += extensions_next_char + 1; // +1 for the comma
    // Comma not needed for JA3S because extensions is the lasts field.
    if (handshake_msg_type != CLIENT_HELLO) {
      ja3_last_byte = state->scratchpad_next_byte - 1;
    }
    debug_print("Extensions: %s\n", extensions);
    debug_print("SPAD: %s\n", state->scratchpad);
    pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_EXTENSIONS, (const unsigned char *) extensions,
                          extensions_next_char);
  }
  // Set elliptic curves
  if ((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES) ||
       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3))) {
    if (ellcurves_present) {
      if (offset + ellcurves_offset + 1 >= data_length) {
        goto end;
      }

      u_int16_t ell_curves_len = ntohs(get_u16(payload, offset + ellcurves_offset));
      uint16_t next_curve = 0;
      char *curves = state->scratchpad + state->scratchpad_next_byte;
      size_t curves_next_char = 0;
      ellcurves_offset += 2; // Skip the length
      while (next_curve < ell_curves_len) {
        if (offset + ellcurves_offset + next_curve + 1 >= data_length) {
          goto end;
        }
        uint16_t curve_id = ntohs(get_u16(payload, offset + ellcurves_offset + next_curve));
        if (!is_grease(curve_id)) {
          curves_next_char += sprintf(curves + curves_next_char, "%d-", curve_id);
        }
        next_curve += 2;
      }
      // Remove last dash
      if (curves_next_char) {
        curves_next_char -= 1;
      }
      sprintf(curves + curves_next_char, ",");
      state->scratchpad_next_byte += curves_next_char + 1; // +1 for the comma
      debug_print("Curves: %s\n", curves);
      debug_print("SPAD: %s\n", state->scratchpad);
      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES, (const unsigned char *) curves,
                            curves_next_char);
    } else {
      sprintf(state->scratchpad + state->scratchpad_next_byte, ",");
      state->scratchpad_next_byte += 1;
    }
  }

  // Set elliptic curves point format
  if ((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS) ||
       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3))) {
    if (ellpoints_present) {
      if (offset + ellpoints_offset >= data_length) {
        goto end;
      }
      uint8_t ell_points_len = get_u8(payload, offset + ellpoints_offset);
      uint16_t next_point = 0;
      char *points = state->scratchpad + state->scratchpad_next_byte;
      size_t points_next_char = 0;
      ellpoints_offset += 1; // Skip the length
      while (next_point < ell_points_len) {
        if (offset + ellpoints_offset + next_point >= data_length) {
          goto end;
        }
        uint8_t point_id = get_u8(payload, offset + ellpoints_offset + next_point);
        if (!is_grease(point_id)) {
          points_next_char += sprintf(points + points_next_char, "%d-", point_id);
        }
        next_point += 1;
      }
      // Remove last dash
      if (points_next_char) {
        points_next_char -= 1;
      }
      points[points_next_char] = '\0';
      state->scratchpad_next_byte += points_next_char;
      debug_print("CurvesPointFmt: %s\n", points);
      debug_print("SPAD: %s\n", state->scratchpad);
      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS, (const unsigned char *) points,
                            points_next_char);
    }
    if (handshake_msg_type == CLIENT_HELLO) {
      ja3_last_byte = state->scratchpad_next_byte;
    }
  }

  // If we found server name, copy it to scratchpad and set field accordingly
  if (server_name) {
    // We can have SNI set in TLS info, but no server name provided
    if (server_name_length > 0) {
      memcpy(state->scratchpad + state->scratchpad_next_byte, server_name, server_name_length);
    }
    pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_SNI,
                          (const unsigned char *) state->scratchpad + state->scratchpad_next_byte, server_name_length);
    state->scratchpad_next_byte += server_name_length;
  }

  // Compute JA3
  pfwl_string_t dummy, dummy2;
  if ((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) &&
      !pfwl_field_string_get(fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, &dummy) &&
      !pfwl_field_string_get(fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, &dummy2)) {
    debug_print("JA3 Fields: %.*s\n", (int) (ja3_last_byte - scratchpad_start), state->scratchpad + scratchpad_start);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, state->scratchpad + scratchpad_start, ja3_last_byte - scratchpad_start);
    unsigned char md5[16];
    MD5_Final(md5, &ctx);
    int n;
    char *ja3_start = state->scratchpad + state->scratchpad_next_byte;
    for (n = 0; n < 16; n++) {
      sprintf(state->scratchpad + state->scratchpad_next_byte, "%02x", md5[n]);
      state->scratchpad_next_byte += 2;
    }
    debug_print("JA3: %.*s\n", 32, ja3_start);
    pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_JA3, (const unsigned char *) ja3_start, 32);
  }
  // TODO: Everytime we write on scratchpad we should check that the max length is not exceeded
end:
  return 2;
}

/* Code fixes courtesy of Alexsandro Brahm <alex@digistar.com.br> */
static int getSSLcertificate(pfwl_state_t *state, pfwl_flow_info_private_t *flow_info_private, const unsigned char *hdr,
                             const unsigned char *payload, size_t data_length, char *buffer, size_t buffer_len,
                             pfwl_field_t *fields, uint32_t *next_server_extension, uint32_t *remaining_extension_len) {
  /*
    Nothing matched so far: let's decode the certificate with some heuristics
    Patches courtesy of Denys Fedoryshchenko <nuclearcat@nuclearcat.com>
  */
  size_t ssl_length = ntohs(get_u16(hdr, 3)) + 5;
  u_int8_t handshake_msg_type =
      hdr[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */

  debug_print("handshake type %d \n", handshake_msg_type);

  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE)) {
    pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE, handshake_msg_type);
  }

  size_t scratchpad_start = state->scratchpad_next_byte;

  if (handshake_msg_type == SERVER_HELLO || handshake_msg_type == CLIENT_HELLO) {
    if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) {
      if (10 > data_length) {
        goto end_notfound;
      }
      uint16_t vernum = ntohs(get_u16(payload, 9));
      pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, vernum);
      if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) {
        char *ver = state->scratchpad + state->scratchpad_next_byte;
        state->scratchpad_next_byte += sprintf(ver, "%d,", vernum);
      }
    }
  }

  memset(buffer, 0, buffer_len);
  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CERTIFICATE) &&
      (handshake_msg_type == SERVER_HELLO || handshake_msg_type == CERTIFICATE)) {
    u_int num_found = 0;

    // Here we are sure we saw the client certificate

    /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
    size_t i;
    int first_payload_byte = 9;
    if (first_payload_byte < 0) {
      first_payload_byte = 0;
    }
    for (i = first_payload_byte; i < data_length - 3; i++) {
      if (((payload[i] == 0x04) && (payload[i + 1] == 0x03) && (payload[i + 2] == 0x0c)) ||
          ((payload[i] == 0x04) && (payload[i + 1] == 0x03) && (payload[i + 2] == 0x13)) ||
          ((payload[i] == 0x55) && (payload[i + 1] == 0x04) && (payload[i + 2] == 0x03))) {
        u_int8_t server_len = payload[i + 3];

        if (payload[i] == 0x55) {
          num_found++;

          if (num_found != 2)
            continue;
        }

        if (server_len + i + 3 < data_length) {
          char *server_name = (char *) &payload[i + 4];
          u_int8_t begin = 0, len, j, num_dots;

          while (begin < server_len) {
            if (!pfwl_isprint(server_name[begin]))
              begin++;
            else
              break;
          }

          // len = pfwl_min(server_len-begin, buffer_len-1);
          if (buffer_len > 0) {
            len = buffer_len - 1;
            strncpy(buffer, &server_name[begin], len);
            buffer[len] = '\0';

            /* We now have to check if this looks like an IP address or host name */
            for (j = 0, num_dots = 0; j < len; j++) {
              if (!pfwl_isprint((buffer[j]))) {
                num_dots = 0; /* This is not what we look for */
                break;
              } else if (buffer[j] == '.') {
                num_dots++;
                if (num_dots >= 2)
                  break;
              }
            }

            if (num_dots >= 2) {
              stripCertificateTrailer(buffer, &buffer_len);
              debug_print("CERT: %s\n", buffer);
              // Copy data into SSL information so that it can be retrieved later
              // We do no use scratchpad as it coulg be bigger than it
              if (flow_info_private->ssl_information.certificates) {
                free(flow_info_private->ssl_information.certificates);
                flow_info_private->ssl_information.certificates = NULL;
              }
              flow_info_private->ssl_information.certificates = calloc(1, buffer_len + 1);
              if (flow_info_private->ssl_information.certificates) {
                memcpy(flow_info_private->ssl_information.certificates, &server_name[begin], buffer_len);
                pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_CERTIFICATE,
                                      (const unsigned char *) flow_info_private->ssl_information.certificates,
                                      buffer_len);
                return (1 /* Server Certificate */);
              }
            }
          }
        }
      }
    }
  }

  if (handshake_msg_type == CLIENT_HELLO || handshake_msg_type == SERVER_HELLO) {
    size_t base_offset = 43;
    if (*next_server_extension) {
      return processExtensions(state, flow_info_private, 0, payload, *remaining_extension_len, *next_server_extension,
                               data_length, buffer, buffer_len, fields, next_server_extension, remaining_extension_len,
                               scratchpad_start, handshake_msg_type);
    }
    if (base_offset + 2 <= data_length) {
      u_int16_t session_id_len = payload[base_offset];

      // TODO: Replace ssl_length with data_length, and if checks are not satisfied manage segmentation
      if ((session_id_len + base_offset + 2) <= ssl_length) {
        size_t offset;
        u_int16_t cypher_len;
        uint cypher_offset;
        if (handshake_msg_type == CLIENT_HELLO) {
          if (session_id_len + base_offset + 1 + 2 > data_length) {
            goto end_notfound;
          }
          cypher_len = ntohs(get_u16(payload, session_id_len + base_offset + 1));
          offset = base_offset + session_id_len + cypher_len + 2;
          cypher_offset = base_offset + session_id_len + 3;
        } else {
          cypher_len = 2;
          offset = base_offset + session_id_len + 2;
          cypher_offset = base_offset + session_id_len + 1;
        }
        debug_print("CypherLen: %d\n", cypher_len);
        if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CIPHER_SUITES) ||
            pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) {
          if (cypher_len) {
            char *cyphers = state->scratchpad + state->scratchpad_next_byte;
            size_t cyphers_next_char = 0;
            if (cypher_offset + cypher_len > data_length) {
              goto end_notfound;
            }
            for (uint i = 0; i < cypher_len - 1u; i += 2) {
              uint16_t cypher_id = ntohs(get_u16(payload, cypher_offset + i));
              if (!is_grease(cypher_id)) {
                cyphers_next_char += sprintf(cyphers + cyphers_next_char, "%d-", cypher_id);
              }
            }
            // Remove last dash
            if (cyphers_next_char) {
              cyphers_next_char -= 1;
            }
            sprintf(cyphers + cyphers_next_char, ",");
            state->scratchpad_next_byte += cyphers_next_char + 1; // +1 for the comma
            debug_print("Cyphers: %s\n", cyphers);
            debug_print("SPAD: %s\n", state->scratchpad);

            pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, (const unsigned char *) cyphers,
                                  cyphers_next_char);
          } else {
            sprintf(state->scratchpad + state->scratchpad_next_byte, ",");
            state->scratchpad_next_byte += 1;
          }
        }

        // Here we are sure we saw the client certificate

        if (offset < ssl_length) {
          u_int16_t compression_len;
          u_int16_t extensions_len;

          offset++;
          if (offset + 1 > data_length) {
            goto end_notfound;
          }
          compression_len = payload[offset];
          offset++;

          debug_print("SSL [compression_len: %u]\n", compression_len);

          // offset += compression_len + 3;
          offset += compression_len;

          if (offset < ssl_length) {
            if (offset + 2 > data_length) {
              goto end_notfound;
            }
            extensions_len = ntohs(get_u16(payload, offset));
            offset += 2;

            debug_print("SSL [extensions_len: %u]\n", extensions_len);

            return processExtensions(state, flow_info_private, offset, payload, extensions_len, 0, data_length, buffer,
                                     buffer_len, fields, next_server_extension, remaining_extension_len,
                                     scratchpad_start, handshake_msg_type);
          }
        }
      }
    }
  }
end_notfound:
  return (0); /* Not found */
}

int inspectHandshake(pfwl_state_t *state, const unsigned char *hdr, const unsigned char *payload, size_t data_length,
                     pfwl_flow_info_private_t *flow, pfwl_field_t *fields, uint32_t *next_server_extension,
                     uint32_t *remaining_extension_len) {
  /* consider only specific SSL packets (handshake) */
  if (hdr[0] == TLS_handshake) {
    if (pfwl_protocol_field_required(state, flow, PFWL_FIELDS_L7_SSL_VERSION)) {
      uint16_t vernum = ntohs(get_u16(payload, 1));
      pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_VERSION, vernum);
    }
    char certificate[64];
    int rc;

    certificate[0] = '\0';
    rc = getSSLcertificate(state, flow, hdr, payload, data_length, certificate, sizeof(certificate), fields,
                           next_server_extension, remaining_extension_len);
    flow->ssl_information.certificate_num_checks++;
    if (rc > 0) {
      flow->ssl_information.certificates_detected++;
      debug_print("***** [SSL] %s\n", certificate);
      // Search for known host in certificate, strlen(certificate)
      return PFWL_PROTOCOL_MATCHES;
    }

    if (flow->ssl_information.certificate_num_checks >= 2) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_MORE_DATA_NEEDED;
}

uint8_t check_ssl(pfwl_state_t *state, const unsigned char *payload, size_t data_length,
                  pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {

  uint8_t ret = PFWL_PROTOCOL_NO_MATCHES;

  flow_info_private->flow_cleaners_dissectors[PFWL_PROTO_L7_SSL] = &ssl_flow_cleaner;

  debug_print("%s\n", "checking ssl..");

  if (pkt_info->l3.protocol == PFWL_PROTO_L3_IPV4) {
    debug_print("SRC %d.%d.%d.%d:%u  DST %d.%d.%d.%d:%u  seq %u\n", (pkt_info->l3.addr_src.ipv4 & 0x000000FF),
                (pkt_info->l3.addr_src.ipv4 & 0x0000FF00) >> 8, (pkt_info->l3.addr_src.ipv4 & 0x00FF0000) >> 16,
                (pkt_info->l3.addr_src.ipv4 & 0xFF000000) >> 24,
                ((pkt_info->l4.port_src & 0xFF) << 8) + ((pkt_info->l4.port_src & 0xFF00) >> 8),

                (pkt_info->l3.addr_dst.ipv4 & 0x000000FF), (pkt_info->l3.addr_dst.ipv4 & 0x0000FF00) >> 8,
                (pkt_info->l3.addr_dst.ipv4 & 0x00FF0000) >> 16, (pkt_info->l3.addr_dst.ipv4 & 0xFF000000) >> 24,
                ((pkt_info->l4.port_dst & 0xFF) << 8) + ((pkt_info->l4.port_dst & 0xFF00) >> 8), pkt_info->l4.seq_num);
  }

  // "analyzed_payload" points to the beginning of a ssl packet
  // It can be packet payload (not to free) or it can be start of previous packet
  // data that have been stored in flow_info_private->ssl_information.ssl_data->packets_data
  unsigned char *analyzed_payload = (unsigned char *) payload;
  size_t analyzed_data_length = data_length;
  size_t ssl_length = 0;
  pfwl_ssl_internal_packet_data_t *data_to_free = NULL;

  if (flow_info_private->ssl_information.ssl_data != NULL) {
    debug_print("prev packet length %u \n",
                flow_info_private->ssl_information.ssl_data->packets_data_len[pkt_info->l4.direction]);
    if (flow_info_private->ssl_information.ssl_data->next_seq_num[pkt_info->l4.direction] == pkt_info->l4.seq_num) {
      debug_print("%s\n", "TCP sequence is correct");

      // Reassemble data with previous data
      memcpy(flow_info_private->ssl_information.ssl_data->packets_data[pkt_info->l4.direction] +
                 flow_info_private->ssl_information.ssl_data->packets_data_len[pkt_info->l4.direction],
             analyzed_payload, analyzed_data_length);

      analyzed_payload = flow_info_private->ssl_information.ssl_data->packets_data[pkt_info->l4.direction];
      analyzed_data_length += flow_info_private->ssl_information.ssl_data->packets_data_len[pkt_info->l4.direction];
      // ss_ldata will be deleted at the end of the function
      data_to_free = flow_info_private->ssl_information.ssl_data;
      flow_info_private->ssl_information.ssl_data = NULL;
    } else {
      debug_print("TCP OUT OF ORDER seq_num %u  prev %u \n",
                  flow_info_private->ssl_information.ssl_data->next_seq_num[pkt_info->l4.direction],
                  pkt_info->l4.seq_num);
      free(flow_info_private->ssl_information.ssl_data);
      flow_info_private->ssl_information.ssl_data = NULL;
    }
  }

  while (analyzed_data_length >= 6) {
    unsigned char *hdr = analyzed_payload;

    // Compute ssl length

    // SSLv3 Record
    if ((hdr[0] == TLS_change_cipher_spec) || (hdr[0] == TLS_handshake) || (hdr[0] == TLS_application_data) ||
        (hdr[0] == TLS_heartbeat) || (hdr[0] == TLS_alert)) {
      // Check Protocol version
      if ((hdr[1] == 0x03) && (hdr[2] == 0x00 || hdr[2] == 0x01)) {
        debug_print("%s\n", "SSL v3 detected");
        flow_info_private->ssl_information.version = PFWL_SSLV3;
      } else if ((hdr[1] == 0x03) && (hdr[2] == 0x02 || hdr[2] == 0x03)) {
        debug_print("%s\n", "TLS v1.2 or v1.3 detected");
        flow_info_private->ssl_information.version = PFWL_TLSV1_2;
      }
      ssl_length = ntohs(get_u16(hdr, 3)) + 5;
    } else if (hdr[2] == 0x01 && hdr[3] == 0x03 && (hdr[4] == 0x00 || hdr[4] == 0x01 || hdr[4] == 0x02)) {
      flow_info_private->ssl_information.version = PFWL_SSLV2;
      debug_print("%s\n", "SSL v2 len match");
      ssl_length = hdr[1] + 2;
    }

    debug_print("SSL length %lu \n", ssl_length);

    if (ssl_length == 0) {
      ret = PFWL_PROTOCOL_NO_MATCHES;
      goto end;
    }

    // Check if we have received all the packets to analyze handshake
    debug_print("ssl_length %lu data_length %lu \n", ssl_length, analyzed_data_length);
    if (analyzed_data_length < ssl_length) {
      goto more_data_needed;
    }

    if (flow_info_private->ssl_information.stage == 0) {
      // SSLv2 Record
      if (hdr[2] == 0x01 && hdr[3] == 0x03 && (hdr[4] == 0x00 || hdr[4] == 0x01 || hdr[4] == 0x02)) {
        flow_info_private->ssl_information.version = PFWL_SSLV2;
        debug_print("%s\n", "SSL v2 len match");

        if (ssl_length == analyzed_data_length) {
#if SSL_BIDIRECTIONAL
          flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
          // packet if full but we need to wait for server answer
          ret = PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
          ret = PFWL_PROTOCOL_MATCHES;
#endif
        }
      }

      // SSLv3 Record
      if ((hdr[0] == TLS_handshake || hdr[0] == TLS_application_data) && hdr[1] == 0x03 &&
          (hdr[2] == 0x00 || hdr[2] == 0x01 || hdr[2] == 0x02 || hdr[2] == 0x03)) {
        if (ssl_length == analyzed_data_length) {
#if SSL_BIDIRECTIONAL
          flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
          // packet if full but we need to wait for server answer
          ret = PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
          ret = PFWL_PROTOCOL_MATCHES;
#endif
        }
      }
    }

#if SSL_BIDIRECTIONAL
    if (flow_info_private->ssl_information.stage != 0) {
      if ((hdr[0] == TLS_handshake || hdr[0] == TLS_application_data) && hdr[1] == 0x03 &&
          (hdr[2] == 0x00 || hdr[2] == 0x01 || hdr[2] == 0x02 || hdr[2] == 0x03)) {
        if ((flow_info_private->ssl_information.version == PFWL_SSLV3 && hdr[0] == TLS_handshake) ||
            (flow_info_private->ssl_information.version == PFWL_TLSV1_2 && hdr[0] == TLS_application_data)) {
          ret = PFWL_PROTOCOL_MATCHES;
        }
      } else if (hdr[2] == 0x01 && hdr[3] == 0x03 && (hdr[4] == 0x00 || hdr[4] == 0x01 || hdr[4] == 0x02) &&
                 flow_info_private->ssl_information.version == PFWL_SSLV2) {
        ret = PFWL_PROTOCOL_MATCHES;
      }
    }
#endif

    if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CERTIFICATE) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_SNI) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS) ||
        pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) {

      ret = inspectHandshake(state, hdr, analyzed_payload, analyzed_data_length, flow_info_private,
                             pkt_info->l7.protocol_fields, &(flow_info_private->ssl_information.next_server_extension),
                             &(flow_info_private->ssl_information.remaining_extension_len));
    }

    analyzed_payload += ssl_length;
    analyzed_data_length -= ssl_length;
    debug_print("processed %lu  remains %lu \n", ssl_length, analyzed_data_length);
  }

more_data_needed:
  if (analyzed_data_length != 0) {
    if (analyzed_data_length < PFWL_SSL_MAX_DATA_SIZE) {
      // We do not have enough data, we need to copy current data and wait for next packet data
      flow_info_private->ssl_information.ssl_data =
          (pfwl_ssl_internal_packet_data_t *) calloc(1, sizeof(pfwl_ssl_internal_packet_data_t));
      if (flow_info_private->ssl_information.ssl_data) {
        memcpy(flow_info_private->ssl_information.ssl_data->packets_data[pkt_info->l4.direction], analyzed_payload,
               analyzed_data_length);
        flow_info_private->ssl_information.ssl_data->packets_data_len[pkt_info->l4.direction] = analyzed_data_length;
        flow_info_private->ssl_information.ssl_data->next_seq_num[pkt_info->l4.direction] = pkt_info->l4.next_seq_num;
      }

      ret = PFWL_PROTOCOL_MORE_DATA_NEEDED;
    } else {
      ret = PFWL_PROTOCOL_ERROR;
    }
  }

end:
  if (data_to_free != NULL) {
    free(data_to_free);
  }
  return ret;
}
