/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "NewIntraFreqCellSI-HCS-ECN0-LCR-r4.h"

asn_TYPE_member_t asn_MBR_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_1[] = {
	{ ATF_POINTER, 1, offsetof(struct NewIntraFreqCellSI_HCS_ECN0_LCR_r4, intraFreqCellID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntraFreqCellID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"intraFreqCellID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NewIntraFreqCellSI_HCS_ECN0_LCR_r4, cellInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellInfoSI_HCS_ECN0_LCR_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellInfo"
		},
};
static const int asn_MAP_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* intraFreqCellID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* cellInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_specs_1 = {
	sizeof(struct NewIntraFreqCellSI_HCS_ECN0_LCR_r4),
	offsetof(struct NewIntraFreqCellSI_HCS_ECN0_LCR_r4, _asn_ctx),
	asn_MAP_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4 = {
	"NewIntraFreqCellSI-HCS-ECN0-LCR-r4",
	"NewIntraFreqCellSI-HCS-ECN0-LCR-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1,
	sizeof(asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1)
		/sizeof(asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1[0]), /* 1 */
	asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1)
		/sizeof(asn_DEF_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_1,
	2,	/* Elements count */
	&asn_SPC_NewIntraFreqCellSI_HCS_ECN0_LCR_r4_specs_1	/* Additional specs */
};

