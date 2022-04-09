/* circ_buf.h
 *
 * Copyright 2022 Zhengyi Fu <tsingyat@outlook.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef CIRC_BUF_H
#define CIRC_BUF_H

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef CIRC_BUF_HAVE_UIO
#if defined(_POSIX_C_SOURCE) || defined(_GNU_SOURCE) ||                        \
	defined(_BSD_SOURCE) || defined(_XOPEN_SOURCE)
#define CIRC_BUF_HAVE_UIO 1
#endif
#endif

#if CIRC_BUF_HAVE_UIO
#include <sys/uio.h>
#endif

struct circ_buf {
	unsigned head;
	unsigned tail;
	unsigned size;
	unsigned _pad[1];
	uint8_t data[];
};

static inline struct circ_buf *circ_buf_alloc(unsigned size)
{
	struct circ_buf *circ;

	assert((size & (size - 1)) == 0);
	if (size == 0 || (size & (size - 1)) != 0) {
		errno = EINVAL;
		return NULL;
	}

	circ = (struct circ_buf *)malloc(sizeof(struct circ_buf) + size);
	if (!circ)
		return NULL;

	circ->size = size;
	circ->head = 0;
	circ->tail = 0;

	memset(circ->data, 0xff, size);

	return circ;
}

static inline void circ_buf_free(struct circ_buf *circ)
{
	if (circ)
		free(circ);
}

static inline int circ_buf_empty(const struct circ_buf *circ)
{
	return circ->head == circ->tail;
}

static inline unsigned circ_buf_count(const struct circ_buf *circ)
{
	return (circ->tail - circ->head) & (circ->size - 1);
}

static inline unsigned circ_buf_space(const struct circ_buf *circ)
{
	return circ->size - 1 - circ_buf_count(circ);
}

static inline unsigned circ_buf_count_to_end(const struct circ_buf *circ)
{
	unsigned end = circ->size - circ->tail;
	unsigned n = (circ->head + end) & (circ->size - 1);
	return n < end ? n : end;
}

static inline unsigned circ_buf_space_to_end(struct circ_buf *circ)
{
	unsigned end = circ->size - 1 - circ->head;
	unsigned n = (end + circ->tail) & (circ->size - 1);
	return n <= end ? n : end + 1;
}

#if CIRC_BUF_HAVE_UIO
static inline void circ_buf_prepare(struct circ_buf *circ,
				    struct iovec iovecs[2], unsigned *nr_vecs)
{
	unsigned tail_i = circ->tail & (circ->size - 1);
	unsigned before_head_i = (circ->head - 1) & (circ->size - 1);

	if (tail_i == before_head_i) {
		*nr_vecs = 0;
		return;
	}

	if (tail_i > before_head_i) {
		iovecs[0].iov_base = &circ->data[tail_i];
		iovecs[0].iov_len = circ->size - tail_i;

		if (before_head_i == 0) {
			*nr_vecs = 1;
			return;
		}
		iovecs[1].iov_base = circ->data;
		iovecs[1].iov_len = before_head_i;

		*nr_vecs = 2;
	} else {
		iovecs[0].iov_base = &circ->data[tail_i];
		iovecs[0].iov_len = before_head_i - tail_i;
		*nr_vecs = 1;
		return;
	}
}
#endif

static inline void circ_buf_commit(struct circ_buf *circ, unsigned n)
{
	assert(circ_buf_space(circ) >= n);
	circ->tail += n;
}

#if CIRC_BUF_HAVE_UIO
static inline void circ_buf_data(struct circ_buf *circ, struct iovec iovecs[2],
				 unsigned *nr_vecs)
{
	unsigned tail_i = circ->tail & (circ->size - 1);
	unsigned head_i = circ->head & (circ->size - 1);

	if (tail_i == head_i) {
		*nr_vecs = 0;
		return;
	}

	if (head_i > tail_i) {
		iovecs[0].iov_base = &circ->data[head_i];
		iovecs[0].iov_len = circ->size - head_i;

		if (tail_i == 0) {
			*nr_vecs = 1;
			return;
		}

		iovecs[1].iov_base = circ->data;
		iovecs[1].iov_len = tail_i - 1;
		*nr_vecs = 2;
		return;
	} else {
		iovecs[0].iov_base = &circ->data[head_i];
		iovecs[0].iov_len = tail_i - head_i;
		*nr_vecs = 1;
		return;
	}
}
#endif

static inline void circ_buf_consume(struct circ_buf *circ, unsigned n)
{
	assert(circ_buf_count(circ) >= n);
	circ->head += n;
}

static inline int circ_buf_read(struct circ_buf *circ, void *__restrict buf,
				unsigned size, unsigned *off)
{
	unsigned head = circ->head + *off;

	if (((circ->tail - head) & (circ->size - 1)) >= size) {
		unsigned count_to_end = circ_buf_count_to_end(circ);
		memcpy(buf, &circ->data[head & (circ->size - 1)],
		       count_to_end > size ? size : count_to_end);
		if (count_to_end < size) {
			memcpy((uint8_t *)buf + count_to_end, circ->data,
			       size - count_to_end);
		}
		*off += size;
		return 0;
	}

	return -EIO;
}

static inline int circ_buf_read_u8(struct circ_buf *circ,
				   uint8_t *__restrict buf, unsigned *off)
{
	return circ_buf_read(circ, buf, 1, off);
}

static inline int circ_buf_read_be16(struct circ_buf *circ, uint16_t *buf,
				     unsigned *off)
{
	uint8_t data[2] = { 0 };

	if (circ_buf_read(circ, data, sizeof(data), off))
		return -EIO;

	*buf = (data[0] << 8) | (data[1] & 0xff);
	return 0;
}

static inline int circ_buf_read_le16(struct circ_buf *circ, uint16_t *buf,
				     unsigned *off)
{
	uint8_t data[2] = { 0 };

	if (circ_buf_read(circ, data, sizeof(data), off))
		return -EIO;

	*buf = data[0] | (data[1] << 8);
	return 0;
}

static inline int circ_buf_read_be32(struct circ_buf *circ,
				     uint32_t *__restrict buf, unsigned *off)
{
	uint8_t data[4] = { 0 };

	if (circ_buf_read(circ, data, sizeof(data), off))
		return -EIO;

	*buf = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	return 0;
}

static inline int circ_buf_read_le32(struct circ_buf *circ,
				     uint32_t *__restrict buf, unsigned *off)
{
	uint8_t data[4] = { 0 };

	if (circ_buf_read(circ, data, sizeof(data), off))
		return -EIO;

	*buf = (data[3] << 24) | (data[2] << 16) | (data[1] << 8) | data[0];
	return 0;
}

static inline int circ_buf_write(struct circ_buf *circ,
				 const void *__restrict buf, unsigned size,
				 unsigned *off)
{
	unsigned tail = circ->tail + *off;

	if (circ->size + circ->head - 1 - tail > size) {
		unsigned space_to_end = circ_buf_space_to_end(circ);
		memcpy(&circ->data[tail], buf,
		       space_to_end > size ? size : space_to_end);
		if (space_to_end < size) {
			memcpy(circ->data, (const uint8_t *)buf + space_to_end,
			       size - space_to_end);
		}
		*off += size;
		return 0;
	}
	return -EIO;
}

static inline int circ_buf_write_u8(struct circ_buf *circ, unsigned value,
				    unsigned *off)
{
	uint8_t data[1];

	data[0] = value & 0xff;
	return circ_buf_write(circ, data, sizeof(data), off);
}

static inline int circ_buf_write_be16(struct circ_buf *circ, unsigned value,
				      unsigned *off)
{
	uint8_t data[2];

	data[0] = (value >> 8) & 0xff;
	data[1] = value & 0xff;

	return circ_buf_write(circ, data, sizeof(data), off);
}

static inline int circ_buf_write_le16(struct circ_buf *circ, unsigned value,
				      unsigned *off)
{
	uint8_t data[2];

	data[0] = value & 0xff;
	data[1] = (value >> 8) & 0xff;

	return circ_buf_write(circ, data, sizeof(data), off);
}

static inline int circ_buf_write_be32(struct circ_buf *circ,
				      uint_least32_t value, unsigned *off)
{
	uint8_t data[4] = { 0 };

	data[0] = (value >> 24) & 0xff;
	data[1] = (value >> 16) & 0xff;
	data[2] = (value >> 8) & 0xff;
	data[3] = value & 0xff;

	return circ_buf_write(circ, data, sizeof(data), off);
}

static inline int circ_buf_write_le32(struct circ_buf *circ,
				      uint_least32_t value, unsigned *off)
{
	uint8_t data[4] = { 0 };

	data[3] = (value >> 24) & 0xff;
	data[2] = (value >> 16) & 0xff;
	data[1] = (value >> 8) & 0xff;
	data[0] = value & 0xff;

	return circ_buf_write(circ, data, sizeof(data), off);
}

#endif /* CIRC_BUF_H */
