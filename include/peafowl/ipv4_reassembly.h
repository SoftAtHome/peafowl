/*
 * ipv4_reassembly.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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

#ifndef PFWL_IPV4_REASSEMBLY_H_
#define PFWL_IPV4_REASSEMBLY_H_

#include <stdint.h>

/* To get the 'fragment offset' part. **/
#define PFWL_IPv4_FRAGMENTATION_OFFSET_MASK 0x1FFF
/* Flag: "More Fragments" */
#define PFWL_IPv4_FRAGMENTATION_MF 0x2000

typedef struct pfwl_ipv4_fragmentation_state pfwl_ipv4_fragmentation_state_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enables the IPv4 defragmentation.
 * @param table_size  The size of the table used to
 *                    store the fragments.
 * @return            A pointer to the IPv4 defragmentation handle.
 */
pfwl_ipv4_fragmentation_state_t *
pfwl_reordering_enable_ipv4_fragmentation(uint16_t table_size);

/**
 * Sets the maximum amount of memory that can be used to store
 * fragments generated by the same source.
 * @param frag_state A pointer to the IPv4 degragmentation handle.
 * @param per_host_memory_limit  The maximum amount of memory that can
 *                               be used to store fragments generated
 *                               by the same source.
 */
void pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(
    pfwl_ipv4_fragmentation_state_t *frag_state,
    uint32_t per_host_memory_limit);

/**
 * Sets the maximum (global) amount of memory that can be used for
 * defragmentation purposes.
 * @param frag_state           A pointer to the IPv4 defragmentation
 *                             handle.
 * @param total_memory_limit   The global memory limit.
 */
void pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(
    pfwl_ipv4_fragmentation_state_t *frag_state, uint32_t total_memory_limit);

/**
 * Sets the maximum amount of time (seconds) which can elapse before
 * the complete defragmentation of the datagram.
 * @param frag_state        A pointer to the IPv4 defragmentation handle.
 * @param timeout_seconds   The timeout (seconds).
 */
void pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(
    pfwl_ipv4_fragmentation_state_t *frag_state, uint8_t timeout_seconds);

/**
 * Disables the IPv4 fragmentation and deallocates the handle.
 * @param frag_state  A pointer to the IPv4 defragmentation handle.
 */
void pfwl_reordering_disable_ipv4_fragmentation(
    pfwl_ipv4_fragmentation_state_t *frag_state);

/**
 * Reassemble the IP datagram if it is fragmented. It is thread safe
 * if and only if PFWL_THREAD_SAFETY_ENABLED == 1.
 * @param state The state for fragmentation support.
 * @param data A pointer to the beginning of IP header.
 * @param current_time The current time, in seconds.
 * @param offset The data offset specified in the ip header.
 * @param more_fragments 1 if the MF flag is set, 0 otherwise.
 * @param tid The thread id.
 * @return Returns NULL if the datagram is a fragment but doesn't fill an
 *         hole. In this case, the content of the datagram has been
 *         copied, so if the user wants, he can release the resources
 *         used to store the received packet.
 *
 *         Returns A pointer to the recomposed datagram if the datagram
 *         is the last fragment of a bigger datagram. This pointer will be
 *         different from data. The user should free() this pointer when
 *         it is no more needed.
 */
unsigned char *pfwl_reordering_manage_ipv4_fragment(
    pfwl_ipv4_fragmentation_state_t *state, const unsigned char *data,
    uint32_t current_time, uint16_t offset, uint8_t more_fragments, int tid);

#ifdef __cplusplus
}
#endif
#endif /* PFWL_IPV4_REASSEMBLY_H_ */
