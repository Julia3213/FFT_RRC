/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "ChannelCodingType.h"

static asn_oer_constraints_t asn_OER_type_ChannelCodingType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_ChannelCodingType_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_ChannelCodingType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ChannelCodingType, choice.noCoding),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"noCoding"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ChannelCodingType, choice.convolutional),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CodingRate,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"convolutional"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ChannelCodingType, choice.turbo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"turbo"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_ChannelCodingType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* noCoding */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* convolutional */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* turbo */
};
asn_CHOICE_specifics_t asn_SPC_ChannelCodingType_specs_1 = {
	sizeof(struct ChannelCodingType),
	offsetof(struct ChannelCodingType, _asn_ctx),
	offsetof(struct ChannelCodingType, present),
	sizeof(((struct ChannelCodingType *)0)->present),
	asn_MAP_ChannelCodingType_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_ChannelCodingType = {
	"ChannelCodingType",
	"ChannelCodingType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_ChannelCodingType_constr_1, &asn_PER_type_ChannelCodingType_constr_1, CHOICE_constraint },
	asn_MBR_ChannelCodingType_1,
	3,	/* Elements count */
	&asn_SPC_ChannelCodingType_specs_1	/* Additional specs */
};

