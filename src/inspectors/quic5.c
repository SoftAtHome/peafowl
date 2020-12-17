/*
 * quic5.c
 *
 * Protocol specification: https://tools.ietf.org/html/draft-tsvwg-quic-protocol-00
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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include "quic_ssl_utils.h"

#define MAX_CONNECTION_ID_LENGTH 	20
#define MAX_VERSION_LENGTH	 	4
#define MAX_STRING_LENGTH	 	256
#define MAX_SALT_LENGTH			20
#define MAX_LABEL_LENGTH		32
#define HASH_SHA2_256_LENGTH		32
#define TLS13_AEAD_NONCE_LENGTH		12

typedef struct {
	unsigned int first_byte;
	size_t dst_conn_id_len;
	unsigned char dst_conn_id[MAX_CONNECTION_ID_LENGTH];
	size_t src_conn_id_len;
	unsigned char src_conn_id[MAX_CONNECTION_ID_LENGTH];
	size_t header_len;
	unsigned char version[MAX_VERSION_LENGTH];
	size_t packet_number;
	size_t packet_number_len;
	size_t payload_len;
	
	unsigned char *decrypted_payload;
	size_t decrypted_payload_len;

	const EVP_CIPHER *quic_cipher_mode;

	unsigned char quic_secret[HASH_SHA2_256_LENGTH];
	size_t quic_secret_len;

	unsigned char quic_key[32];
	size_t quic_key_len;
	unsigned char quic_hp[32];
	size_t quic_hp_len;
	unsigned char quic_iv[TLS13_AEAD_NONCE_LENGTH];
	size_t quic_iv_len;
	unsigned int has_tls13_record;
} quic_t;

/* Quic Versions */
typedef enum {
	VER_Q024=0x51303234,
	VER_Q025=0x51303235,
	VER_Q030=0x51303330,
	VER_Q033=0x51303333,
	VER_Q034=0x51303334,
	VER_Q035=0x51303335,
	VER_Q037=0x51303337,
	VER_Q039=0x51303339,
	VER_Q043=0x51303433,
	VER_Q046=0x51303436,
	VER_Q050=0x51303530,
	VER_T050=0x54303530,
	VER_T051=0x54303531,
	VER_MVFST_22=0xfaceb001,
	VER_MVFST_27=0xfaceb002,
	VER_MVFST_EXP=0xfaceb00e,
} quic_version_t;

#define PFWL_DEBUG_DISS_QUIC 1
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_DISS_QUIC)                                               \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

static size_t convert_length_connection(size_t len){
  switch(len){
    case 0x0C:
      return 8;
    case 0x08:
      return 4;
    case 0x04:
      return 1;
    case 0x00:
      return 0;
    default:
      return 0;
  }
}

static size_t convert_length_sequence(size_t len){
  switch(len){
    case 0x30:
      return 6;
    case 0x20:
      return 4;
    case 0x10:
      return 2;
    case 0x00:
      return 1;
    default:
      return 0;
  }
}

static uint16_t quic_getu16(const unsigned char* start, size_t offset){
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return get_u16((const char*) start, offset);
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t x = get_u16((const char*) start, offset);
  return x << 8 | x >> 8;
#else
#error "Please fix <bits/endian.h>"
#endif
}

static uint32_t quic_getu32(const unsigned char* start, size_t offset){
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return get_u32((const char*) start, offset);
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint32_t x = get_u32((const char*) start, offset);
  return ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24));
#else
#error "Please fix <bits/endian.h>"
#endif
}

/* Quic variable length Integer decoding algorithm */
size_t quic_get_variable_len(const unsigned char *app_data, size_t offset, uint64_t *var_len) {
	size_t 		mbit	 	= app_data[offset] >> 6;
	size_t 		len	 	= 0;

	switch(mbit) {
		case 0:
			len = 1;
			*var_len = (uint64_t)(app_data[offset] & 0x3F);
			break;
		case 1:
			*var_len = ((uint64_t)(app_data[offset] & 0x3F) << 8) + (uint64_t)(app_data[offset + 1] & 0xFF);
			len = 2;
			break;
		case 2:
			*var_len = ((uint64_t)(app_data[offset] & 0x3F) << 24) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 16)
				 + ((uint64_t)(app_data[offset + 2] & 0xFF) << 8) + (uint64_t)(app_data[offset + 3] & 0xFF);
			len = 4;
			break;
		case 3:
			*var_len = ((uint64_t)(app_data[offset] & 0x3F) << 56) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 48) 
				+ ((uint64_t)(app_data[offset + 2] & 0xFF) << 40) + ((uint64_t)(app_data[offset + 3] & 0xFF) << 32)
				+ ((uint64_t)(app_data[offset + 4] & 0xFF) << 24) + ((uint64_t)(app_data[offset + 5] & 0xFF) << 16) 
				+ ((uint64_t)(app_data[offset + 6] & 0xFF) << 8) + (uint64_t)(app_data[offset + 7] & 0xFF);
			len = 8;
			break;
		default:
			len = 0; /* error should not happen */
	}
	return len;
}

/* START OF CODE THAT NEEDS TO BE REWRITTEN */
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static void phton64(uint8_t *p, uint64_t v) {
	p[0] = (uint8_t)(v >> 56);
	p[1] = (uint8_t)(v >> 48);
	p[2] = (uint8_t)(v >> 40);
	p[3] = (uint8_t)(v >> 32);
	p[4] = (uint8_t)(v >> 24);
	p[5] = (uint8_t)(v >> 16);
	p[6] = (uint8_t)(v >> 8);
	p[7] = (uint8_t)(v >> 0);
}

static uint64_t pntoh64(const void *p) {
	return (uint64_t)*((const uint8_t *)(p)+0)<<56|
		(uint64_t)*((const uint8_t *)(p)+1)<<48|
		(uint64_t)*((const uint8_t *)(p)+2)<<40|
		(uint64_t)*((const uint8_t *)(p)+3)<<32|
		(uint64_t)*((const uint8_t *)(p)+4)<<24|
		(uint64_t)*((const uint8_t *)(p)+5)<<16|
		(uint64_t)*((const uint8_t *)(p)+6)<<8|
		(uint64_t)*((const uint8_t *)(p)+7)<<0;
}

static void debug_print_rawfield(const unsigned char *app_data, size_t start_offset, size_t len) {
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%02X", app_data[start_offset + i]);
	}
	printf("\n");
}

static void debug_print_charfield(const unsigned char *app_data, size_t start_offset, size_t len) {
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%C", app_data[start_offset + i]);
	}
	printf("\n");
}

static void *memdup(const uint8_t *orig, size_t len) {
	void *dest = malloc(len);
	if(dest)
		memcpy(dest, orig, len);
	return dest;
}

/**
 * Compute the client and server initial secrets given Connection ID "cid".
 */
static int quic_derive_initial_secrets(quic_t *quic_info) {
	/*
	 * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
	 *
	 * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
	 *
	 * client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "client in", "", Hash.length)
	 *
	 * Hash for handshake packets is SHA-256 (output size 32).
	 */
	static const uint8_t ver_q050_salt[MAX_SALT_LENGTH] = { 0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45 };
	static const uint8_t ver_t050_salt[MAX_SALT_LENGTH] = { 0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10 };
	static const uint8_t ver_t051_salt[MAX_SALT_LENGTH] = { 0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d };
	const uint8_t	*salt; 
	uint32_t v	= ntohl(*(uint32_t *)(&quic_info->version[0]));

	switch (v) {
		case VER_Q050:
			salt = ver_q050_salt;
			quic_info->has_tls13_record = 0;
			break;

		case VER_T050:
			salt = ver_t050_salt;
			quic_info->has_tls13_record = 1;
			break;

		case VER_T051:
			salt = ver_t051_salt;
			quic_info->has_tls13_record = 1;
			break;
		default:
			printf("Error matching the quic version to a salt using standard salt instead\n");
			salt = ver_q050_salt;
			quic_info->has_tls13_record = 0;
	}

	uint8_t secret[HASH_SHA2_256_LENGTH];
	const size_t s_len = HASH_SHA2_256_LENGTH;
	int len = HKDF_Extract(salt, (sizeof(uint8_t) * MAX_SALT_LENGTH), quic_info->dst_conn_id, quic_info->dst_conn_id_len, secret, s_len);	
	if(0 > len) {
		printf("Failed to extract secrets\n");
		return -1;
	}

	unsigned char   label[MAX_LABEL_LENGTH] = { 0 };
	size_t          label_len = 0;
	/* TODO MAKE 32 configurable or at least explain why it is 32 */
        label_len = hkdf_create_tls13_label(32, "client in", label, sizeof(label));
        quic_info->quic_secret_len = HKDF_Expand(secret, len, label, label_len, quic_info->quic_secret, s_len);
	return 0;
}

/*
 * (Re)initialize the PNE/PP ciphers using the given cipher algorithm.
 * If the optional base secret is given, then its length MUST match the hash
 * algorithm output.
 */
static int quic_cipher_prepare(quic_t *quic_info)
{
	//TODO MAKE CIPHER LEN DYNAMIC
	uint32_t 	cipher_keylen 	= 16; /* 128 bit cipher length == 16 bytes storage */
        unsigned char   label_key[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_key_len 	= 0;
	unsigned char   label_iv[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_iv_len 	= 0;
	unsigned char   label_hp[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_hp_len 	= 0;

	label_key_len 	= hkdf_create_tls13_label(cipher_keylen, "quic key", label_key, sizeof(label_key));
        label_iv_len 	= hkdf_create_tls13_label(TLS13_AEAD_NONCE_LENGTH, "quic iv", label_iv, sizeof(label_iv));
        label_hp_len 	= hkdf_create_tls13_label(cipher_keylen, "quic hp", label_hp, sizeof(label_hp));

	quic_info->quic_key_len = HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_key, label_key_len, quic_info->quic_key, cipher_keylen);
	quic_info->quic_iv_len	= HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_iv, label_iv_len, quic_info->quic_iv, TLS13_AEAD_NONCE_LENGTH);
	quic_info->quic_hp_len	= HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_hp, label_hp_len, quic_info->quic_hp, cipher_keylen);
	return 0;
}

/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-12.3
 */
static int quic_decrypt_message(quic_t *quic_info, const uint8_t *packet_payload, uint32_t packet_payload_len)
{
	uint8_t *header;
	uint8_t nonce[TLS13_AEAD_NONCE_LENGTH];
	uint8_t atag[16];

	/* Copy header, but replace encrypted first byte and PKN by plaintext. */
	header = (uint8_t *)memdup(packet_payload, quic_info->header_len);
	if(!header)
		return -1;
	header[0] = quic_info->first_byte;
	for(uint32_t i = 0; i < quic_info->packet_number_len; i++) {
		header[quic_info->header_len - 1 - i] = (uint8_t)(quic_info->packet_number >> (8 * i));
	}

	/* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
	quic_info->decrypted_payload_len = packet_payload_len - (quic_info->header_len + 16);
	if(quic_info->decrypted_payload_len == 0) {
		printf("Decryption not possible, ciphertext is too short\n");
		free(header);
		return -1;
	}
	quic_info->decrypted_payload = (unsigned char *)memdup(packet_payload + quic_info->header_len, quic_info->decrypted_payload_len);
	if(!quic_info->decrypted_payload) {
		free(header);
		return -1;
	}
	memcpy(atag, packet_payload + quic_info->header_len + quic_info->decrypted_payload_len, 16);
	memcpy(nonce, quic_info->quic_iv, TLS13_AEAD_NONCE_LENGTH);
	/* Packet number is left-padded with zeroes and XORed with write_iv */
	phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ quic_info->packet_number);

        /* Initial packets are protected with AEAD_AES_128_GCM. */
        quic_info->decrypted_payload_len = aes_gcm_decrypt(quic_info->decrypted_payload, quic_info->decrypted_payload_len,
		EVP_aes_128_gcm(), header, quic_info->header_len, atag, quic_info->quic_key, nonce, sizeof(nonce), quic_info->decrypted_payload);
	free(header);
	return 0;
}

static int remove_header_protection(quic_t *quic_info, const unsigned char *app_data) {
	unsigned char 	ciphertext[128] = { 0 };
	// https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.1 
	unsigned char 	first_byte  	= app_data[0];
	unsigned char 	mask[5] 	= { 0 };


	/* Sample is always 16 bytes and starts after PKN (assuming length 4).
		https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.2 */
	size_t 		sample_pos 	=  quic_info->header_len + 4;
	size_t 		sample_len 	= 16;
	unsigned char 	*sample 	= (unsigned char *)app_data + sample_pos;

	/* Encrypt in-place with AES-ECB and extract the mask. */
        /* Packet numbers are protected with AES128-CTR */
	int res = aes_encrypt(sample, sample_len, EVP_aes_128_ecb(), quic_info->quic_hp, NULL, ciphertext);
	if (0 > res) {
		printf("Error encrypting sample\n");
		return -1;
	}

	memcpy(mask, ciphertext, sizeof(mask));
	if((first_byte & 0x80) == 0x80) {
		/* Long header: 4 bits masked */
		first_byte ^= mask[0] & 0x0f;
	} else {
		/* Short header: 5 bits masked */
		first_byte ^= mask[0] & 0x1f;
	}
	quic_info->packet_number_len = (first_byte & 0x03) + 1;

	quic_info->packet_number = 0;
	for(size_t i = 0; i < quic_info->packet_number_len; i++) {
		quic_info->packet_number |= (size_t)(app_data[quic_info->header_len + i] ^ mask[1 + i]) << (8 * (quic_info->packet_number_len - 1 - i));
	}
	/* Increase header length with packet number length */
	quic_info->header_len += quic_info->packet_number_len;
	quic_info->first_byte = first_byte;
	return 0;
}

int decrypt_first_packet(quic_t *quic_info, const unsigned char *app_data, size_t data_length) {
	
	if(0 > quic_derive_initial_secrets(quic_info)) {
		printf("Error quic_derive_initial_secrets\n");
		return -1;
	}

	if(0 > quic_cipher_prepare(quic_info)) {
		printf("Error quic_cipher_prepare\n");
		return -1;
	}

	if (0 > remove_header_protection(quic_info, app_data)) {
		printf("Error removing error protection\n");
		return -1;
	}

	if (0 > quic_decrypt_message(quic_info, app_data, data_length)) {
		printf("Error decrypting message\n");
		return -1;
	}
	return 0;
}

void quic_parse_google_user_agent(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
        char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
        memcpy(scratchpad, data, len);
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, scratchpad, len);
        state->scratchpad_next_byte += len;
}

void tls_parse_quic_transport_params(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	size_t		pointer = 0;
	size_t		TLVtype = 0;
	size_t 		TLVlen 	= 0;
	for (pointer = 0; pointer <len; pointer += TLVlen) {
		pointer += quic_get_variable_len(data, pointer, &TLVtype);
		TLVlen = data[pointer];
		pointer++;
		//printf("parameter TLV %08X TLV Size %02d\n", TLVtype, TLVlen);
		switch(TLVtype) {
			case 0x3129:
				quic_parse_google_user_agent(state, data + pointer, TLVlen, pkt_info, flow_info_private);
			default:
				break;
		}

	}
}

void tls_parse_servername(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	size_t		pointer = 0;
	uint16_t 	list_len = ntohs(*(uint16_t *)(data));
	size_t 		type 	= data[2];
	uint16_t 	server_len = ntohs(*(uint16_t *)(data + 3));
	pointer	= 2 + 1 + 2;

	char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
	memcpy(scratchpad, data + pointer, server_len);
	pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, scratchpad, server_len);
	state->scratchpad_next_byte += server_len;
}

void tls_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	size_t pointer;
	size_t TLVlen;
	size_t TLVtype;
	for (pointer = 0; pointer < len; pointer += TLVlen) {
		TLVtype = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		TLVlen = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		//printf("TLV %02d TLV Size %02d\n", TLVtype, TLVlen);
		switch(TLVtype) {
			/* Server Name */
			case 0:
				tls_parse_servername(state, data + pointer, TLVlen, pkt_info, flow_info_private);
				break;
				/* Extension quic transport parameters */
			case 65445:
				tls_parse_quic_transport_params(state, data + pointer, TLVlen, pkt_info, flow_info_private);
				break;
			default:
				break;
		}	

	}
}

void check_tls13(pfwl_state_t *state, const unsigned char *tls_data, size_t tls_data_length, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
        /* Finger printing */
        unsigned char ja3_string[1024];
        size_t ja3_string_len;

	size_t 		tls_pointer	= 0;

	/* Parse TLS record header */
	size_t tls_record_frame_type = tls_data[tls_pointer];
	tls_pointer++;

	size_t tls_record_offset     = tls_data[tls_pointer];
	tls_pointer++;

	uint16_t tls_record_len	     = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
	tls_pointer += 2;

	/* Parse TLS Handshake protocol */
	size_t	handshake_type = tls_data[tls_pointer];
	tls_pointer++;

	size_t 	length = (tls_data[tls_pointer] << 16) + (tls_data[tls_pointer+1] << 8) + tls_data[tls_pointer+2];
	tls_pointer += 3;

	uint16_t tls_version = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
	tls_pointer += 2;

	/* Build JA3 string */
	ja3_string_len = sprintf(ja3_string, "%d,", tls_version);

	if (handshake_type == 1) { /* We only inspect client hello which has a type equal to 1 */	
		/* skipping random data 32 bytes */
		tls_pointer += 32;

		/* skipping legacy_session_id one byte */
		tls_pointer += 1;

		/* Cipher suites and length */
		uint16_t cipher_suite_len = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
		tls_pointer += 2;

		/* use content of cipher suite for building the JA3 hash */
		for (size_t i = 0; i < cipher_suite_len; i += 2) {
			uint16_t cipher_suite = ntohs(*(uint16_t *)(tls_data + tls_pointer + i));
			ja3_string_len += sprintf(ja3_string + ja3_string_len, "%d-", cipher_suite);
		}
		if (cipher_suite_len) {
			ja3_string_len--; //remove last dash (-) from ja3_string
		}
		ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");
		tls_pointer += cipher_suite_len;

		/* compression methods length */
		size_t compression_methods_len = tls_data[tls_pointer];
		tls_pointer++;

		/* Skip compression methods */
		tls_pointer += compression_methods_len;

		/* Extension length */
		uint16_t ext_len = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
		tls_pointer += 2;

		/* Add Extension length to the ja3 string */
		ja3_string_len += sprintf(ja3_string + ja3_string_len, "%d,,", ext_len);

		/* lets iterate over the exention list */
		unsigned const char *ext_data = tls_data + tls_pointer;
		tls_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private);
	}
	printf("JA3 String %s\n", ja3_string);
}

uint8_t check_quic5(pfwl_state_t *state, const unsigned char *app_data,
		size_t data_length, pfwl_dissection_info_t *pkt_info,
		pfwl_flow_info_private_t *flow_info_private){

	quic_t 	quic_info;
	char	*scratchpad = state->scratchpad + state->scratchpad_next_byte;

	memset(&quic_info, 0, sizeof(quic_t));
	if(data_length >= 1200){
		size_t connection_id_len = convert_length_connection(app_data[0] & 0x0C);
		size_t unused_bits = app_data[0] & 0xC0;
		int has_version = app_data[0] & 0x01;

		size_t header_form = (app_data[0] & 0x80) >> 7; // 1000 0000
		size_t bit2 = (app_data[0] & 0x40) >> 6; // 0100 0000
		size_t bit3 = (app_data[0] & 0x20) >> 5; // 0010 0000
		size_t bit4 = (app_data[0] & 0x10) >> 4; // 0001 0000
		size_t bit5 = (app_data[0] & 0x08) >> 3; // 0000 1000
		size_t bit6 = (app_data[0] & 0x04) >> 2; // 0000 0100
		size_t bit7 = (app_data[0] & 0x02) >> 1; // 0000 0010
		size_t bit8 = (app_data[0] & 0x01);      // 0000 0001	

		size_t version_offset 		= 0;
		size_t header_estimation 	= 0;

		if(header_form) { /* Long packet type */
			version_offset = 1; // 1 byte
			quic_info.header_len++; // First byte header

			memcpy(quic_info.version, &app_data[1], 4);

			uint32_t *t = (uint32_t *)&app_data[1];
			quic_info.header_len += 4; /* version (4 bytes) */

			quic_info.dst_conn_id_len = app_data[quic_info.header_len];
			quic_info.header_len++; //1 byte destionation connection length 

			memcpy(quic_info.dst_conn_id, &app_data[quic_info.header_len], quic_info.dst_conn_id_len);
			quic_info.header_len = quic_info.header_len + quic_info.dst_conn_id_len; /* destination connection id length */

			quic_info.src_conn_id_len = app_data[quic_info.header_len];
			quic_info.header_len++; //1 byte source connection length 

			memcpy(quic_info.src_conn_id, &app_data[quic_info.header_len], quic_info.src_conn_id_len);
			quic_info.header_len = quic_info.header_len + quic_info.src_conn_id_len; /* source connection id length */ 	

			size_t token_len = 0;
			quic_info.header_len += quic_get_variable_len(app_data, quic_info.header_len, &token_len);
			quic_info.header_len += token_len;

			quic_info.header_len += quic_get_variable_len(app_data, quic_info.header_len, &quic_info.payload_len);

			if (0 > decrypt_first_packet(&quic_info, app_data, data_length)) {
				return PFWL_PROTOCOL_NO_MATCHES;
			}
			header_estimation  = quic_info.header_len;

		} else { /* Short packet type */
			return PFWL_PROTOCOL_NO_MATCHES;
		}

		if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_VERSION)) {
			scratchpad = state->scratchpad + state->scratchpad_next_byte;
			memcpy(scratchpad, quic_info.version, 4);
			pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, scratchpad, 4);
			state->scratchpad_next_byte += 4;
		}


		if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI) || 
				pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) {
			unsigned int 	frame_type 		= quic_info.decrypted_payload[0];
			unsigned int 	offset 			= quic_info.decrypted_payload[1];
			size_t 		crypto_data_size 	= 0;
			size_t 		crypto_data_len		= quic_get_variable_len(quic_info.decrypted_payload, 2, &crypto_data_size);
			/* According to wireshark chlo_start could also be quic_info.decrypted_payload + 2 (frame_type || offset) + crypto_data_len */

			if (quic_info.has_tls13_record) {
				check_tls13(state, quic_info.decrypted_payload, quic_info.decrypted_payload_len, pkt_info, flow_info_private);
			} else {
				/* PLZ Move me to a function */
				const unsigned char* chlo_start = (const unsigned char*) pfwl_strnstr((const char*) quic_info.decrypted_payload, "CHLO", quic_info.decrypted_payload_len);
				if(chlo_start){
					size_t num_tags = (chlo_start[4] & 0xFF) + ((chlo_start[5] & 0xFF) << 8);
					size_t start_tags = ((const unsigned char*) chlo_start - quic_info.decrypted_payload)  + 8;
					size_t start_content = start_tags + num_tags*8;
					u_int32_t last_offset_end = 0;

					for(size_t i = start_tags; i < crypto_data_size; i += 8){
						u_int32_t offset_end 	= 0;
						u_int32_t length	= 0;
						u_int32_t offset	= 0;
						if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)) {
							if(quic_info.decrypted_payload[i]     == 'S' &&
									quic_info.decrypted_payload[i + 1] == 'N' &&
									quic_info.decrypted_payload[i + 2] == 'I' &&
									quic_info.decrypted_payload[i + 3] == 0){ 
								offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
								length = offset_end - last_offset_end;
								offset = last_offset_end;
								if(start_content + offset + length  <= data_length){
									scratchpad = state->scratchpad + state->scratchpad_next_byte;
									memcpy(scratchpad, &quic_info.decrypted_payload[start_content + offset], length);
									pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, scratchpad, length);
									state->scratchpad_next_byte += length;
								} 
							}	
						}
						if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) { 
							if (quic_info.decrypted_payload[i] == 'U' &&
									quic_info.decrypted_payload[i+1] == 'A' &&
									quic_info.decrypted_payload[i+2] == 'I' &&
									quic_info.decrypted_payload[i+3] == 'D') {
								offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
								length = offset_end - last_offset_end;
								offset = last_offset_end;
								if(start_content + offset + length  <= data_length){
									scratchpad = state->scratchpad + state->scratchpad_next_byte; 
									memcpy(scratchpad, &quic_info.decrypted_payload[start_content + offset], length);
									pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, scratchpad, length);
									state->scratchpad_next_byte += length;
								}

							}
						}
						last_offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
					}
				}
			}
		}
		free(quic_info.decrypted_payload);
		return PFWL_PROTOCOL_MATCHES;
	}
	return PFWL_PROTOCOL_NO_MATCHES;
}
#else
uint8_t check_quic5(pfwl_state_t *state, const unsigned char *app_data,
		size_t data_length, pfwl_dissection_info_t *pkt_info,
		pfwl_flow_info_private_t *flow_info_private){
	return PFWL_PROTOCOL_NO_MATCHES;
}
#endif
