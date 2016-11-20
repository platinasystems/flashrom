/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2012 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __LIBFLASHROM_H__
#define __LIBFLASHROM_H__ 1

#include <stdarg.h>

int fl_init(int perform_selfcheck);
int fl_shutdown(void);
/** @ingroup fl-general */
enum fl_log_level { /* This has to match enum msglevel. */
	FL_MSG_ERROR	= 0,
	FL_MSG_INFO	= 1,
	FL_MSG_DEBUG	= 2,
	FL_MSG_DEBUG2	= 3,
	FL_MSG_SPEW	= 4,
};
/** @ingroup fl-general */
typedef int(fl_log_callback_t)(enum fl_log_level, const char *format, va_list);
void fl_set_log_callback(fl_log_callback_t *);

int fl_programmer_init(const char *prog_name, const char *prog_params);
int fl_programmer_shutdown(void);

struct flashctx;
typedef struct flashctx fl_flashctx_t;
int fl_flash_probe(fl_flashctx_t **, const char *chip_name);
size_t fl_flash_getsize(const fl_flashctx_t *);
int fl_flash_erase(fl_flashctx_t *);
void fl_flash_release(fl_flashctx_t *);

enum fl_flag {
	FL_FLAG_FORCE,
	FL_FLAG_FORCE_BOARDMISMATCH,
	FL_FLAG_VERIFY_AFTER_WRITE,
	FL_FLAG_VERIFY_WHOLE_CHIP,
};
void fl_flag_set(fl_flashctx_t *, enum fl_flag, bool value);
bool fl_flag_get(const fl_flashctx_t *, enum fl_flag);

int fl_image_read(fl_flashctx_t *, void *buffer, size_t buffer_len);
int fl_image_write(fl_flashctx_t *, const void *buffer, size_t buffer_len);
int fl_image_verify(fl_flashctx_t *, const void *buffer, size_t buffer_len);

struct fl_layout;
typedef struct fl_layout fl_layout_t;
int fl_layout_read_from_ifd(fl_flashctx_t *, fl_layout_t **, const void *dump, size_t len);
int fl_layout_include_region(fl_layout_t *, const char *name);
void fl_layout_release(fl_layout_t *);
void fl_layout_set(fl_flashctx_t *, const fl_layout_t *);

#endif				/* !__LIBFLASHROM_H__ */
