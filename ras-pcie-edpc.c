// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2025 Alibaba Inc
 */

#include <pci/pci.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ras-pcie-edpc.h"
#include "ras-logger.h"
#include "types.h"

#define EDPC_DEVICE "EDPC_DEVICE"
#define EDPC_CONTROL_CONFIG 0x9

#define PCI_EXP_DPC_CTL			0x06	/* DPC control */
#define  PCI_EXP_DPC_CTL_EN_FATAL	0x0001	/* Enable trigger on ERR_FATAL message */
#define  PCI_EXP_DPC_CTL_EN_NONFATAL	0x0002	/* Enable trigger on ERR_NONFATAL message */
#define  PCI_EXP_DPC_CTL_INT_EN		0x0008	/* DPC Interrupt Enable */

#define PCI_EXP_DPC_CTL_EN_MASK	(PCI_EXP_DPC_CTL_EN_FATAL | \
	PCI_EXP_DPC_CTL_EN_NONFATAL)

static char *edpc_str[] = {
	[PCI_EXP_DPC_CTL_EN_FATAL] = "Fatal Error",
	[PCI_EXP_DPC_CTL_EN_NONFATAL] = "Non-Fatal Error",
};

static void set_edpc(struct pci_dev *dev)
{
	struct pci_cap *cap;
	u16 control;
	int need_config = 0;

	pci_fill_info(dev, PCI_FILL_EXT_CAPS);
	cap = pci_find_cap(dev, PCI_EXT_CAP_ID_DPC, PCI_CAP_EXTENDED);
	if (!cap)
		return;

	control = pci_read_word(dev, cap->addr + PCI_EXP_DPC_CTL);
	need_config = ((control & (PCI_EXP_DPC_CTL_INT_EN | PCI_EXP_DPC_CTL_EN_MASK)) == EDPC_CONTROL_CONFIG) ? 0 : 1;
	log(TERM, LOG_INFO, "Device %x:%x:%x.%x origin EDPC %s and triggered for %s, %s need config\n",
	    dev->domain, dev->bus, dev->dev, dev->func,
	    (control & PCI_EXP_DPC_CTL_INT_EN) ? "enabled" : "disabled",
	    edpc_str[control & PCI_EXP_DPC_CTL_EN_MASK],
	    need_config ? "" : "not");

	if (need_config) {
		control &= ~(PCI_EXP_DPC_CTL_INT_EN | PCI_EXP_DPC_CTL_EN_MASK);
		control |= EDPC_CONTROL_CONFIG;
		pci_write_word(dev, cap->addr + 6, control);
		log(TERM, LOG_INFO, "Device %x:%x:%x.%x EDPC %s and triggered for %s\n",
		    dev->domain, dev->bus, dev->dev, dev->func,
		    (control & PCI_EXP_DPC_CTL_INT_EN) ? "enabled" : "disabled",
		    edpc_str[control & PCI_EXP_DPC_CTL_EN_MASK]);
	}
}

static struct pci_filter *config_pcie_edpc_device(struct pci_access *pacc, char *names, int *len)
{
	int i;
	struct pci_filter *filter = NULL;
	char *token, *err, pci_names[MAX_PATH + 1];

	strscpy(pci_names, names, sizeof(names));
	for (i = 0; pci_names[i] != '\0'; i++)
		if (pci_names[i] == ',')
			(*len)++;

	filter = calloc(*len, sizeof(struct pci_filter));
	if (!filter)
		return NULL;

	i = 0;
	token = strtok(pci_names, ",");
	while (token) {
		pci_filter_init(pacc, &filter[i]);
		err = pci_filter_parse_slot(&filter[i++], token);
		if (err) {
			free(filter);
			log(TERM, LOG_ERR, "Invalid PCI device name %s\n", err);
			return NULL;
		}
		token = strtok(NULL, ",");
	}

	log(TERM, LOG_ERR, "Config PCIE EDPC for: %s\n", names);

	return filter;
}

int config_pcie_edpc(void)
{
	struct pci_access *pacc;
	struct pci_dev *dev;
	int ret = 0, len = 1, i;
	char *pci_names;
	struct pci_filter *filter = NULL;

	pacc = pci_alloc();
	if (!pacc)
		return -1;

	pci_init(pacc);
	pci_scan_bus(pacc);

	pci_names = getenv(EDPC_DEVICE);
	if (pci_names && strlen(pci_names) != 0) {
		filter = config_pcie_edpc_device(pacc, pci_names, &len);
		if (!filter)
			goto free;
	} else {
		len = 0;
	}

	for (dev = pacc->devices; dev; dev = dev->next) {
		if (len) {
			for (i = 0; i < len; i++)
				if (pci_filter_match(&filter[i], dev))
					set_edpc(dev);
		} else {
			set_edpc(dev);
		}
	}

free:
	pci_cleanup(pacc);
	free(filter);
	return ret;
}
