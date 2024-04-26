/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RLC-Info.h"

#include "UL-RLC-Mode.h"
#include "DL-RLC-Mode.h"
asn_TYPE_member_t asn_MBR_RLC_Info_1[] = {
	{ ATF_POINTER, 2, offsetof(struct RLC_Info, ul_RLC_Mode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_UL_RLC_Mode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-RLC-Mode"
		},
	{ ATF_POINTER, 1, offsetof(struct RLC_Info, dl_RLC_Mode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_DL_RLC_Mode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-RLC-Mode"
		},
};
static const int asn_MAP_RLC_Info_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_RLC_Info_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RLC_Info_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ul-RLC-Mode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-RLC-Mode */
};
asn_SEQUENCE_specifics_t asn_SPC_RLC_Info_specs_1 = {
	sizeof(struct RLC_Info),
	offsetof(struct RLC_Info, _asn_ctx),
	asn_MAP_RLC_Info_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_RLC_Info_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RLC_Info = {
	"RLC-Info",
	"RLC-Info",
	&asn_OP_SEQUENCE,
	asn_DEF_RLC_Info_tags_1,
	sizeof(asn_DEF_RLC_Info_tags_1)
		/sizeof(asn_DEF_RLC_Info_tags_1[0]), /* 1 */
	asn_DEF_RLC_Info_tags_1,	/* Same as above */
	sizeof(asn_DEF_RLC_Info_tags_1)
		/sizeof(asn_DEF_RLC_Info_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RLC_Info_1,
	2,	/* Elements count */
	&asn_SPC_RLC_Info_specs_1	/* Additional specs */
};
