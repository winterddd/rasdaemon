/*
 * The code below came from Tony Luck's mcelog code,
 * released under GNU Public General License, v.2
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <string.h>

#include "bitfield.h"
#include "ras-mce-handler.h"

/* See IA32 SDM Vol3B Table 16-24 */

static char *pcu_1[] = {
	[0x00] = "No Error",
	[0x09] = "MC_MESSAGE_CHANNEL_TIMEOUT",
	[0x13] = "MC_DMI_TRAINING_TIMEOUT",
	[0x15] = "MC_DMI_CPU_RESET_ACK_TIMEOUT",
	[0x1E] = "MC_VR_ICC_MAX_LT_FUSED_ICC_MAX",
	[0x25] = "MC_SVID_COMMAN_TIMEOUT",
	[0x26] = "MCA_PKGC_DIRECT_WAKE_RING_TIMEOUT",
	[0x29] = "MC_VR_VOUT_MAC_LT_FUSED_SVID",
	[0x2B] = "MC_PKGC_WATCHDOG_HANG_CBZ_DOWN",
	[0x2C] = "MC_PKGC_WATCHDOG_HANG_CBZ_UP",
	[0x44] = "MC_CRITICAL_VR_FAILED",
	[0x46] = "MC_VID_RAMP_DOWN_FAILED",
	[0x49] = "MC_SVID_WRITE_REG_VOUT_MAX_FAILED",
	[0x4B] = "MC_BOOT_VID_TIMEOUT_DRAM_0",
	[0x4F] = "MC_SVID_COMMAND_ERROR",
	[0x52] = "MC_FIVR_CATAS_OVERVOL_FAULT",
	[0x53] = "MC_FIVR_CATAS_OVERCUR_FAULT",
	[0x57] = "MC_SVID_PKGC_REQUEST_FAILED",
	[0x58] = "MC_SVID_IMON_REQUEST_FAILED",
	[0x59] = "MC_SVID_ALERT_REQUEST_FAILED",
	[0x62] = "MC_INVALID_PKGS_RSP_QPI",
	[0x64] = "MC_INVALID_PKG_STATE_CONFIG",
	[0x67] = "MC_HA_IMC_RW_BLOCK_ACK_TIMEOUT",
	[0x6A] = "MC_MSGCH_PMREQ_CMP_TIMEOUT",
	[0x72] = "MC_WATCHDOG_TIMEOUT_PKGS_MASTER",
	[0x81] = "MC_RECOVERABLE_DIE_THERMAL_TOO_HOT"
};

static struct field pcu_mc4[] = {
	FIELD(24, pcu_1),
	{}
};

/* See IA32 SDM Vol3B Table 16-18 */

static struct field memctrl_mc9[] = {
	SBITFIELD(16, "Address parity error"),
	SBITFIELD(17, "HA Wrt buffer Data parity error"),
	SBITFIELD(18, "HA Wrt byte enable parity error"),
	SBITFIELD(19, "Corrected patrol scrub error"),
	SBITFIELD(20, "Uncorrected patrol scrub error"),
	SBITFIELD(21, "Corrected spare error"),
	SBITFIELD(22, "Uncorrected spare error"),
	SBITFIELD(23, "Corrected memory read error"),
	SBITFIELD(24, "iMC, WDB, parity errors"),
	{}
};

void broadwell_de_decode_model(struct ras_events *ras, struct mce_event *e)
{
	uint64_t status = e->status;
	uint32_t mca = status & 0xffff;
	unsigned int rank0 = -1, rank1 = -1, chan;

	switch (e->bank) {
	case 4:
		switch (EXTRACT(status, 0, 15) & ~(1ull << 12)) {
		case 0x402: case 0x403:
			mce_snprintf(e->mcastatus_msg, "Internal errors ");
			break;
		case 0x406:
			mce_snprintf(e->mcastatus_msg, "Intel TXT errors ");
			break;
		case 0x407:
			mce_snprintf(e->mcastatus_msg, "Other UBOX Internal errors ");
			break;
		}
		if (EXTRACT(status, 16, 19) & 3)
			mce_snprintf(e->mcastatus_msg, "PCU internal error ");
		if (EXTRACT(status, 20, 23) & 4)
			mce_snprintf(e->mcastatus_msg, "Ubox error ");
		decode_bitfield(e, status, pcu_mc4);
		break;
	case 9: case 10:
		mce_snprintf(e->mcastatus_msg, "MemCtrl: ");
		decode_bitfield(e, status, memctrl_mc9);
		break;
	}

	/*
	 * Memory error specific code. Returns if the error is not a MC one
	 */

	/* Check if the error is at the memory controller */
	if ((mca >> 7) != 1)
		return;

	/* Ignore unless this is an corrected extended error from an iMC bank */
	if (e->bank < 9 || e->bank > 16 || (status & MCI_STATUS_UC) ||
	    !test_prefix(7, status & 0xefff))
		return;

	/*
	 * Parse the reported channel and ranks
	 */

	chan = EXTRACT(status, 0, 3);
	if (chan == 0xf)
		return;

	mce_snprintf(e->mc_location, "memory_channel=%d", chan);

	if (EXTRACT(e->misc, 62, 62)) {
		rank0 = EXTRACT(e->misc, 46, 50);
		if (EXTRACT(e->misc, 63, 63))
			rank1 = EXTRACT(e->misc, 51, 55);
	}

	/*
	 * FIXME: The conversion from rank to dimm requires to parse the
	 * DMI tables and call failrank2dimm().
	 */
	if (rank0 != -1 && rank1 != -1)
		mce_snprintf(e->mc_location, "ranks=%d and %d",
			     rank0, rank1);
	else if (rank0 != -1)
		mce_snprintf(e->mc_location, "rank=%d", rank0);
}
