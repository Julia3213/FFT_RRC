/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RB-InformationSetup-r4.h"

#include "PDCP-Info-r4.h"
asn_TYPE_member_t asn_MBR_RB_InformationSetup_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RB_InformationSetup_r4, rb_Identity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-Identity"
		},
	{ ATF_POINTER, 1, offsetof(struct RB_InformationSetup_r4, pdcp_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PDCP_Info_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pdcp-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RB_InformationSetup_r4, rlc_InfoChoice),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RLC_InfoChoice,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rlc-InfoChoice"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RB_InformationSetup_r4, rb_MappingInfo),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_MappingInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-MappingInfo"
		},
};
static const int asn_MAP_RB_InformationSetup_r4_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_RB_InformationSetup_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RB_InformationSetup_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rb-Identity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pdcp-Info */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* rlc-InfoChoice */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* rb-MappingInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_RB_InformationSetup_r4_specs_1 = {
	sizeof(struct RB_InformationSetup_r4),
	offsetof(struct RB_InformationSetup_r4, _asn_ctx),
	asn_MAP_RB_InformationSetup_r4_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RB_InformationSetup_r4_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RB_InformationSetup_r4 = {
	"RB-InformationSetup-r4",
	"RB-InformationSetup-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_RB_InformationSetup_r4_tags_1,
	sizeof(asn_DEF_RB_InformationSetup_r4_tags_1)
		/sizeof(asn_DEF_RB_InformationSetup_r4_tags_1[0]), /* 1 */
	asn_DEF_RB_InformationSetup_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_RB_InformationSetup_r4_tags_1)
		/sizeof(asn_DEF_RB_InformationSetup_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RB_InformationSetup_r4_1,
	4,	/* Elements count */
	&asn_SPC_RB_InformationSetup_r4_specs_1	/* Additional specs */
};

