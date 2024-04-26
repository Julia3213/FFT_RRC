/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "NewInterFreqCellSI-RSCP-LCR-r4.h"

#include "FrequencyInfo.h"
asn_TYPE_member_t asn_MBR_NewInterFreqCellSI_RSCP_LCR_r4_1[] = {
	{ ATF_POINTER, 2, offsetof(struct NewInterFreqCellSI_RSCP_LCR_r4, interFreqCellID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterFreqCellID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqCellID"
		},
	{ ATF_POINTER, 1, offsetof(struct NewInterFreqCellSI_RSCP_LCR_r4, frequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequencyInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewInterFreqCellSI_RSCP_LCR_r4, cellInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellInfoSI_RSCP_LCR_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellInfo"
		},
};
static const int asn_MAP_NewInterFreqCellSI_RSCP_LCR_r4_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NewInterFreqCellSI_RSCP_LCR_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interFreqCellID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* frequencyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* cellInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_NewInterFreqCellSI_RSCP_LCR_r4_specs_1 = {
	sizeof(struct NewInterFreqCellSI_RSCP_LCR_r4),
	offsetof(struct NewInterFreqCellSI_RSCP_LCR_r4, _asn_ctx),
	asn_MAP_NewInterFreqCellSI_RSCP_LCR_r4_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_NewInterFreqCellSI_RSCP_LCR_r4_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4 = {
	"NewInterFreqCellSI-RSCP-LCR-r4",
	"NewInterFreqCellSI-RSCP-LCR-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1,
	sizeof(asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1)
		/sizeof(asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1[0]), /* 1 */
	asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1)
		/sizeof(asn_DEF_NewInterFreqCellSI_RSCP_LCR_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NewInterFreqCellSI_RSCP_LCR_r4_1,
	3,	/* Elements count */
	&asn_SPC_NewInterFreqCellSI_RSCP_LCR_r4_specs_1	/* Additional specs */
};

