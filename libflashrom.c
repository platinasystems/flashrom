/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2012, 2016 secunet Security Networks AG
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
/**
 * @mainpage
 *
 * Have a look at the Modules section for a function reference.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "flash.h"
#include "programmer.h"
#include "layout.h"
#include "ich_descriptors.h"
#include "libflashrom.h"

/**
 * @defgroup fl-general General
 * @{
 */

/** Pointer to log callback function. */
static fl_log_callback_t *fl_log_callback = NULL;

/**
 * @brief Initialize libflashrom.
 *
 * @param perform_selfcheck If not zero, perform a self check.
 * @return 0 on success
 */
int fl_init(const int perform_selfcheck)
{
	if (perform_selfcheck && selfcheck())
		return 1;
	myusec_calibrate_delay();
	return 0;
}

/**
 * @brief Shut down libflashrom.
 * @return 0 on success
 */
int fl_shutdown(void)
{
	return 0; /* TODO: nothing to do? */
}

/* TODO: fl_set_loglevel()? do we need it?
         For now, let the user decide in his callback. */

/**
 * @brief Set the log callback function.
 *
 * Set a callback function which will be invoked whenever libflashrom wants
 * to output messages. This allows frontends to do whatever they see fit with
 * such messages, e.g. write them to syslog, or to file, or print them in a
 * GUI window, etc.
 *
 * @param log_callback Pointer to the new log callback function.
 */
void fl_set_log_callback(fl_log_callback_t *const log_callback)
{
	fl_log_callback = log_callback;
}
/** @private */
int print(const enum msglevel level, const char *const fmt, ...)
{
	if (fl_log_callback) {
		int ret;
		va_list args;
		va_start(args, fmt);
		ret = fl_log_callback(level, fmt, args);
		va_end(args);
		return ret;
	}
	return 0;
}

/** @} */ /* end fl-general */



/**
 * @defgroup fl-query Querying
 * @{
 */

/* TBD */

/** @} */ /* end fl-query */



/**
 * @defgroup fl-prog Programmers
 * @{
 */

/**
 * @brief Initialize the specified programmer.
 *
 * @param prog_name Name of the programmer to initialize.
 * @param prog_param Pointer to programmer specific parameters.
 * @return 0 on success
 */
int fl_programmer_init(const char *const prog_name, const char *const prog_param)
{
	unsigned prog;

	for (prog = 0; prog < PROGRAMMER_INVALID; prog++) {
		if (strcmp(prog_name, programmer_table[prog].name) == 0)
			break;
	}
	if (prog >= PROGRAMMER_INVALID) {
		msg_ginfo("Error: Unknown programmer \"%s\". Valid choices are:\n", prog_name);
		list_programmers_linebreak(0, 80, 0);
		return 1;
	}
	return programmer_init(prog, prog_param);
}

/**
 * @brief Shut down the initialized programmer.
 *
 * @return 0 on success
 */
int fl_programmer_shutdown(void)
{
	return programmer_shutdown();
}

/* TODO: fl_programmer_capabilities()? */

/** @} */ /* end fl-prog */



/**
 * @defgroup fl-flash Flash chips
 * @{
 */

/**
 * @brief Probe for a flash chip.
 *
 * Probes for a flash chip and returns a flash context, that can be used
 * later with flash chip and @ref fl-ops "image operations", if exactly one
 * matching chip is found.
 *
 * @param[out] flashctx Points to a pointer of type fl_flashctx_t that will
 *                      be set if exactly one chip is found. *flashctx has
 *                      to be freed by the caller with @ref fl_flash_release.
 * @param[in] chip_name Name of a chip to probe for, or NULL to probe for
 *                      all known chips.
 * @return 0 on success,
 *         3 if multiple chips were found,
 *         2 if no chip was found,
 *         or 1 on any other error.
 */
int fl_flash_probe(struct flashctx **const flashctx, const char *const chip_name)
{
	int i, ret = 2;
	struct flashctx second_flashctx = { 0, };

	chip_to_probe = chip_name; /* chip_to_probe is global in flashrom.c */

	*flashctx = malloc(sizeof(**flashctx));
	if (!*flashctx)
		return 1;
	memset(*flashctx, 0, sizeof(**flashctx));

	for (i = 0; i < registered_master_count; ++i) {
		int flash_idx = -1;
		if (!ret || (flash_idx = probe_flash(&registered_masters[i], 0, *flashctx, 0)) != -1) {
			ret = 0;
			/* We found one chip, now check that there is no second match. */
			if (probe_flash(&registered_masters[i], flash_idx + 1, &second_flashctx, 0) != -1) {
				ret = 3;
				break;
			}
		}
	}
	if (ret) {
		free(*flashctx);
		*flashctx = NULL;
	}
	return ret;
}

/**
 * @brief Returns the size of the specified flash chip in bytes.
 *
 * @param flashctx The queried flash context.
 * @return Size of flash chip in bytes.
 */
size_t fl_flash_getsize(const struct flashctx *const flashctx)
{
	return flashctx->chip->total_size << 10;
}

/**
 * @brief Free a flash context.
 *
 * @param flashctx Flash context to free.
 */
void fl_flash_release(struct flashctx *const flashctx)
{
	free(flashctx);
}

/**
 * @brief Set a flag in the given flash context.
 *
 * @param flashctx Flash context to alter.
 * @param flag	   Flag that is to be set / cleared.
 * @param value	   Value to set.
 */
void fl_flag_set(fl_flashctx_t *const flashctx, const enum fl_flag flag, const bool value)
{
	switch (flag) {
		case FL_FLAG_FORCE:			flashctx->flags.force = value; break;
		case FL_FLAG_FORCE_BOARDMISMATCH:	flashctx->flags.force_boardmismatch = value; break;
		case FL_FLAG_VERIFY_AFTER_WRITE:	flashctx->flags.verify_after_write = value; break;
		case FL_FLAG_VERIFY_WHOLE_CHIP:		flashctx->flags.verify_whole_chip = value; break;
	}
}

/**
 * @brief Return the current value of a flag in the given flash context.
 *
 * @param flashctx Flash context to read from.
 * @param flag	   Flag to be read.
 * @return Current value of the flag.
 */
bool fl_flag_get(const fl_flashctx_t *const flashctx, const enum fl_flag flag)
{
	switch (flag) {
		case FL_FLAG_FORCE:			return flashctx->flags.force;
		case FL_FLAG_FORCE_BOARDMISMATCH:	return flashctx->flags.force_boardmismatch;
		case FL_FLAG_VERIFY_AFTER_WRITE:	return flashctx->flags.verify_after_write;
		case FL_FLAG_VERIFY_WHOLE_CHIP:		return flashctx->flags.verify_whole_chip;
		default:				return false;
	}
}

/** @} */ /* end fl-flash */



/**
 * @defgroup fl-layout Layout handling
 * @{
 */

/**
 * @brief Mark given region as included.
 *
 * @param layout The layout to alter.
 * @param name   The name of the region to include.
 *
 * @return 0 on success,
 *         1 if the given name can't be found.
 */
int fl_layout_include_region(fl_layout_t *const layout, const char *name)
{
	size_t i;
	for (i = 0; i < layout->num_entries; ++i) {
		if (!strcmp(layout->entries[i].name, name)) {
			layout->entries[i].included = true;
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Read a layout from the Intel ICH descriptor in the flash.
 *
 * Optionally verify that the layout matches the one in the given
 * descriptor dump.
 *
 * @param flashctx Flash context to read the descriptor from flash.
 * @param layout   Pointer that getwhere to store the layout.
 * @param dump     The descriptor dump to compare to or NULL.
 * @param len      The length of the descriptor dump.
 *
 * @return 0 on success,
 *         5 if the descriptors don't match,
 *         4 if the descriptor dump couldn't be parsed,
 *         3 if the descriptor on flash couldn't be parsed,
 *         2 if the descriptor on flash couldn't be read,
 *         1 on any other error.
 */
int fl_layout_read_from_ifd(struct flashctx *const flashctx, fl_layout_t **const layout,
			    const void *const dump, const size_t len)
{
	struct fl_layout_ich dump_layout;
	int ret = 1;

	void *const desc = malloc(0x1000);
	struct fl_layout_ich *const chip_layout = malloc(sizeof(*chip_layout));
	if (!desc || !chip_layout) {
		msg_gerr("Out of memory!\n");
		goto _free_ret;
	}

	if (prepare_flash_access(flashctx, true, false, false, false))
		goto _free_ret;

	msg_cinfo("Reading ich descriptor... ");
	if (flashctx->chip->read(flashctx, desc, 0, 0x1000)) {
		msg_cerr("Read operation failed!\n");
		msg_cinfo("FAILED.\n");
		ret = 2;
		goto _unmap_ret;
	}
	msg_cinfo("done.\n");

	if (layout_from_ich_descriptors(chip_layout, desc, 0x1000)) {
		ret = 3;
		goto _unmap_ret;
	}

	if (dump) {
		if (layout_from_ich_descriptors(&dump_layout, dump, len)) {
			ret = 4;
			goto _unmap_ret;
		}

		if (chip_layout->base.num_entries != dump_layout.base.num_entries ||
		    memcmp(chip_layout->entries, dump_layout.entries, sizeof(dump_layout.entries))) {
			ret = 5;
			goto _unmap_ret;
		}
	}

	*layout = (struct fl_layout *)chip_layout;
	ret = 0;

_unmap_ret:
	unmap_flash(flashctx);
_free_ret:
	if (ret)
		free(chip_layout);
	free(desc);
	return ret;
}

/**
 * @brief Free a layout.
 *
 * @param layout Layout to free.
 */
void fl_layout_release(struct fl_layout *const layout)
{
	free(layout);
}

/**
 * @brief Set the active layout for a flash context.
 *
 * Note: This just sets a pointer. The caller must not release the layout
 *       as long as he uses it through the given flash context.
 *
 * @param flashctx Flash context whose layout will be set.
 * @param layout   Layout to bet set.
 */
void fl_layout_set(struct flashctx *const flashctx, const struct fl_layout *const layout)
{
	flashctx->layout = layout;
}

/** @} */ /* end fl-layout */
