/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Paul Fox <pgf@laptop.org>
 * Copyright (C) 2009, 2010 Carl-Daniel Hailfinger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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

#if CONFIG_FT2232_SPI == 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "flash.h"
#include "chipdrivers.h"
#include "spi.h"
#include <ftdi.h>

/*
 * The 'H' chips can run internally at either 12MHz or 60MHz.
 * The non-H chips can only run at 12MHz.
 */
#define CLOCK_5X 1

/*
 * In either case, the divisor is a simple integer clock divider.
 * If CLOCK_5X is set, this divisor divides 30MHz, else it divides 6MHz.
 */
#define DIVIDE_BY 3  /* e.g. '3' will give either 10MHz or 2MHz SPI clock. */

#define BITMODE_BITBANG_NORMAL	1
#define BITMODE_BITBANG_SPI	2

static struct ftdi_context ftdic_context;

int send_buf(struct ftdi_context *ftdic, const unsigned char *buf, int size)
{
	int r;
	r = ftdi_write_data(ftdic, (unsigned char *) buf, size);
	if (r < 0) {
		msg_perr("ftdi_write_data: %d, %s\n", r,
				ftdi_get_error_string(ftdic));
		return 1;
	}
	return 0;
}

int get_buf(struct ftdi_context *ftdic, const unsigned char *buf, int size)
{
	int r;
	r = ftdi_read_data(ftdic, (unsigned char *) buf, size);
	if (r < 0) {
		msg_perr("ftdi_read_data: %d, %s\n", r,
				ftdi_get_error_string(ftdic));
		return 1;
	}
	return 0;
}

int ft2232_spi_init(void)
{
	int f;
	struct ftdi_context *ftdic = &ftdic_context;
	unsigned char buf[512];
	char *portpos = NULL;
	int ft2232_type = FTDI_FT4232H;
	enum ftdi_interface ft2232_interface = INTERFACE_B;

	if (ftdi_init(ftdic) < 0) {
		msg_perr("ftdi_init failed\n");
		return EXIT_FAILURE; // TODO
	}

	if (programmer_param && !strlen(programmer_param)) {
		free(programmer_param);
		programmer_param = NULL;
	}
	if (programmer_param) {
		if (strstr(programmer_param, "2232"))
			ft2232_type = FTDI_FT2232H;
		if (strstr(programmer_param, "4232"))
			ft2232_type = FTDI_FT4232H;
		portpos = strstr(programmer_param, "port=");
		if (portpos) {
			portpos += 5;
			switch (toupper(*portpos)) {
			case 'A':
				ft2232_interface = INTERFACE_A;
				break;
			case 'B':
				ft2232_interface = INTERFACE_B;
				break;
			default:
				msg_perr("Invalid interface specified, "
					"using default.\n");
			}
		}
		free(programmer_param);
	}
	msg_pdbg("Using device type %s ",
		     (ft2232_type == FTDI_FT2232H) ? "2232H" : "4232H");
	msg_pdbg("interface %s\n",
		     (ft2232_interface == INTERFACE_A) ? "A" : "B");

	f = ftdi_usb_open(ftdic, 0x0403, ft2232_type);

	if (f < 0 && f != -5) {
		msg_perr("Unable to open FTDI device: %d (%s)\n", f,
				ftdi_get_error_string(ftdic));
		exit(-1); // TODO
	}

	if (ftdi_set_interface(ftdic, ft2232_interface) < 0) {
		msg_perr("Unable to select interface: %s\n",
				ftdic->error_str);
	}

	if (ftdi_usb_reset(ftdic) < 0) {
		msg_perr("Unable to reset FTDI device\n");
	}

	if (ftdi_set_latency_timer(ftdic, 2) < 0) {
		msg_perr("Unable to set latency timer\n");
	}

	if (ftdi_write_data_set_chunksize(ftdic, 512)) {
		msg_perr("Unable to set chunk size\n");
	}

	if (ftdi_set_bitmode(ftdic, 0x00, BITMODE_BITBANG_SPI) < 0) {
		msg_perr("Unable to set bitmode to SPI\n");
	}

#if CLOCK_5X
	msg_pdbg("Disable divide-by-5 front stage\n");
	buf[0] = 0x8a;		/* Disable divide-by-5. */
	if (send_buf(ftdic, buf, 1))
		return -1;
#define MPSSE_CLK 60.0

#else

#define MPSSE_CLK 12.0

#endif
	msg_pdbg("Set clock divisor\n");
	buf[0] = 0x86;		/* command "set divisor" */
	/* valueL/valueH are (desired_divisor - 1) */
	buf[1] = (DIVIDE_BY - 1) & 0xff;
	buf[2] = ((DIVIDE_BY - 1) >> 8) & 0xff;
	if (send_buf(ftdic, buf, 3))
		return -1;

	msg_pdbg("SPI clock is %fMHz\n",
	       (double)(MPSSE_CLK / (((DIVIDE_BY - 1) + 1) * 2)));

	/* Disconnect TDI/DO to TDO/DI for loopback. */
	msg_pdbg("No loopback of TDI/DO TDO/DI\n");
	buf[0] = 0x85;
	if (send_buf(ftdic, buf, 1))
		return -1;

	msg_pdbg("Set data bits\n");
	/* Set data bits low-byte command:
	 *  value: 0x08  CS=high, DI=low, DO=low, SK=low
	 *    dir: 0x0b  CS=output, DI=input, DO=output, SK=output
	 */
#define CS_BIT 0x08
	buf[0] = SET_BITS_LOW;
	buf[1] = CS_BIT;
	buf[2] = 0x0b;
	if (send_buf(ftdic, buf, 3))
		return -1;

	// msg_pdbg("\nft2232 chosen\n");

	buses_supported = CHIP_BUSTYPE_SPI;
	spi_controller = SPI_CONTROLLER_FT2232;

	return 0;
}

int ft2232_spi_send_command(unsigned int writecnt, unsigned int readcnt,
		const unsigned char *writearr, unsigned char *readarr)
{
	struct ftdi_context *ftdic = &ftdic_context;
	static unsigned char *buf = NULL;
	/* failed is special. We use bitwise ops, but it is essentially bool. */
	int i = 0, ret = 0, failed = 0;
	int bufsize;
	static int oldbufsize = 0;

	if (writecnt > 65536 || readcnt > 65536)
		return SPI_INVALID_LENGTH;

	/* buf is not used for the response from the chip. */
	bufsize = max(writecnt + 9, 260 + 9);
	/* Never shrink. realloc() calls are expensive. */
	if (bufsize > oldbufsize) {
		buf = realloc(buf, bufsize);
		if (!buf) {
			msg_perr("Out of memory!\n");
			exit(1);
		}
		oldbufsize = bufsize;
	}

	/*
	 * Minimize USB transfers by packing as many commands as possible
	 * together. If we're not expecting to read, we can assert CS#, write,
	 * and deassert CS# all in one shot. If reading, we do three separate
	 * operations.
	 */
	msg_pspew("Assert CS#\n");
	buf[i++] = SET_BITS_LOW;
	buf[i++] = 0 & ~CS_BIT; /* assertive */
	buf[i++] = 0x0b;

	if (writecnt) {
		buf[i++] = 0x11;
		buf[i++] = (writecnt - 1) & 0xff;
		buf[i++] = ((writecnt - 1) >> 8) & 0xff;
		memcpy(buf + i, writearr, writecnt);
		i += writecnt;
	}

	/*
	 * Optionally terminate this batch of commands with a
	 * read command, then do the fetch of the results.
	 */
	if (readcnt) {
		buf[i++] = 0x20;
		buf[i++] = (readcnt - 1) & 0xff;
		buf[i++] = ((readcnt - 1) >> 8) & 0xff;
		ret = send_buf(ftdic, buf, i);
		failed = ret;
		/* We can't abort here, we still have to deassert CS#. */
		if (ret)
			msg_perr("send_buf failed before read: %i\n",
				ret);
		i = 0;
		if (ret == 0) {
			/*
			 * FIXME: This is unreliable. There's no guarantee that
			 * we read the response directly after sending the read
			 * command. We may be scheduled out etc.
			 */
			ret = get_buf(ftdic, readarr, readcnt);
			failed |= ret;
			/* We can't abort here either. */
			if (ret)
				msg_perr("get_buf failed: %i\n", ret);
		}
	}

	msg_pspew("De-assert CS#\n");
	buf[i++] = SET_BITS_LOW;
	buf[i++] = CS_BIT;
	buf[i++] = 0x0b;
	ret = send_buf(ftdic, buf, i);
	failed |= ret;
	if (ret)
		msg_perr("send_buf failed at end: %i\n", ret);

	return failed ? -1 : 0;
}

int ft2232_spi_read(struct flashchip *flash, uint8_t *buf, int start, int len)
{
	/* Maximum read length is 64k bytes. */
	return spi_read_chunked(flash, buf, start, len, 64 * 1024);
}

int ft2232_spi_write_256(struct flashchip *flash, uint8_t *buf)
{
	int total_size = 1024 * flash->total_size;

	spi_disable_blockprotect();
	/* Erase first. */
	msg_pinfo("Erasing flash before programming... ");
	if (erase_flash(flash)) {
		msg_perr("ERASE FAILED!\n");
		return -1;
	}
	msg_pinfo("done.\n");
	msg_pdbg("total_size is %d\n", total_size);
	return spi_write_chunked(flash, buf, 0, total_size, 256);
}

#endif
