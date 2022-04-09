/* container_of.h
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

#ifndef CONTAINER_OF_H
#define CONTAINER_OF_H

#include <stddef.h>

#ifndef container_of
#ifdef __GNUC__
#define container_of(ptr, type, member)                                       \
  ({                                                                          \
    __typeof__ (((type *)0)->member) *_ptr = (ptr);                           \
    (type *)((char *)_ptr - offsetof (type, member));                         \
  })
#else
#define container_of(ptr, type, member)                                       \
  ((type *)((char *)(ptr) - offsetof (type, member)))
#endif
#endif

#endif /* CONTAINER_OF_H */

