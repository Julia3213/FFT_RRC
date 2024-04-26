/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "InterFreqCellInfoSI-List-HCS-ECN0.h"

#include "RemovedInterFreqCellList.h"
#include "NewInterFreqCellSI-List-HCS-ECN0.h"
asn_TYPE_member_t asn_MBR_InterFreqCellInfoSI_List_HCS_ECN0_1[] = {
	{ ATF_POINTER, 2, offsetof(struct InterFreqCellInfoSI_List_HCS_ECN0, removedInterFreqCellList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RemovedInterFreqCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"removedInterFreqCellList"
		},
	{ ATF_POINTER, 1, offsetof(struct InterFreqCellInfoSI_List_HCS_ECN0, newInterFreqCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NewInterFreqCellSI_List_HCS_ECN0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"newInterFreqCellList"
		},
};
static const int asn_MAP_InterFreqCellInfoSI_List_HCS_ECN0_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterFreqCellInfoSI_List_HCS_ECN0_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* removedInterFreqCellList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* newInterFreqCellList */
};
asn_SEQUENCE_specifics_t asn_SPC_InterFreqCellInfoSI_List_HCS_ECN0_specs_1 = {
	sizeof(struct InterFreqCellInfoSI_List_HCS_ECN0),
	offsetof(struct InterFreqCellInfoSI_List_HCS_ECN0, _asn_ctx),
	asn_MAP_InterFreqCellInfoSI_List_HCS_ECN0_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_InterFreqCellInfoSI_List_HCS_ECN0_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0 = {
	"InterFreqCellInfoSI-List-HCS-ECN0",
	"InterFreqCellInfoSI-List-HCS-ECN0",
	&asn_OP_SEQUENCE,
	asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1,
	sizeof(asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1)
		/sizeof(asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1[0]), /* 1 */
	asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1)
		/sizeof(asn_DEF_InterFreqCellInfoSI_List_HCS_ECN0_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InterFreqCellInfoSI_List_HCS_ECN0_1,
	2,	/* Elements count */
	&asn_SPC_InterFreqCellInfoSI_List_HCS_ECN0_specs_1	/* Additional specs */
};
