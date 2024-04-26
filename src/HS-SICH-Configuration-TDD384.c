/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "HS-SICH-Configuration-TDD384.h"

static asn_oer_constraints_t asn_OER_type_midambleAllocationMode_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_midambleAllocationMode_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ueSpecificMidamble_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode__ueSpecificMidamble, midambleShift),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftLong,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleShift"
		},
};
static const ber_tlv_tag_t asn_DEF_ueSpecificMidamble_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ueSpecificMidamble_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* midambleShift */
};
static asn_SEQUENCE_specifics_t asn_SPC_ueSpecificMidamble_specs_6 = {
	sizeof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode__ueSpecificMidamble),
	offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode__ueSpecificMidamble, _asn_ctx),
	asn_MAP_ueSpecificMidamble_tag2el_6,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueSpecificMidamble_6 = {
	"ueSpecificMidamble",
	"ueSpecificMidamble",
	&asn_OP_SEQUENCE,
	asn_DEF_ueSpecificMidamble_tags_6,
	sizeof(asn_DEF_ueSpecificMidamble_tags_6)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_6[0]) - 1, /* 1 */
	asn_DEF_ueSpecificMidamble_tags_6,	/* Same as above */
	sizeof(asn_DEF_ueSpecificMidamble_tags_6)
		/sizeof(asn_DEF_ueSpecificMidamble_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ueSpecificMidamble_6,
	1,	/* Elements count */
	&asn_SPC_ueSpecificMidamble_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_midambleAllocationMode_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode, choice.defaultMidamble),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"defaultMidamble"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode, choice.ueSpecificMidamble),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_ueSpecificMidamble_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ueSpecificMidamble"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_midambleAllocationMode_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* defaultMidamble */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ueSpecificMidamble */
};
static asn_CHOICE_specifics_t asn_SPC_midambleAllocationMode_specs_4 = {
	sizeof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode),
	offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode, _asn_ctx),
	offsetof(struct HS_SICH_Configuration_TDD384__midambleAllocationMode, present),
	sizeof(((struct HS_SICH_Configuration_TDD384__midambleAllocationMode *)0)->present),
	asn_MAP_midambleAllocationMode_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_midambleAllocationMode_4 = {
	"midambleAllocationMode",
	"midambleAllocationMode",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_midambleAllocationMode_constr_4, &asn_PER_type_midambleAllocationMode_constr_4, CHOICE_constraint },
	asn_MBR_midambleAllocationMode_4,
	2,	/* Elements count */
	&asn_SPC_midambleAllocationMode_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_HS_SICH_Configuration_TDD384_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384, timeslotNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslotNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384, channelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelisationCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384, midambleAllocationMode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_midambleAllocationMode_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleAllocationMode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HS_SICH_Configuration_TDD384, midambleconfiguration),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleConfigurationBurstType1and3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleconfiguration"
		},
};
static const ber_tlv_tag_t asn_DEF_HS_SICH_Configuration_TDD384_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HS_SICH_Configuration_TDD384_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslotNumber */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* channelisationCode */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* midambleAllocationMode */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* midambleconfiguration */
};
asn_SEQUENCE_specifics_t asn_SPC_HS_SICH_Configuration_TDD384_specs_1 = {
	sizeof(struct HS_SICH_Configuration_TDD384),
	offsetof(struct HS_SICH_Configuration_TDD384, _asn_ctx),
	asn_MAP_HS_SICH_Configuration_TDD384_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_HS_SICH_Configuration_TDD384 = {
	"HS-SICH-Configuration-TDD384",
	"HS-SICH-Configuration-TDD384",
	&asn_OP_SEQUENCE,
	asn_DEF_HS_SICH_Configuration_TDD384_tags_1,
	sizeof(asn_DEF_HS_SICH_Configuration_TDD384_tags_1)
		/sizeof(asn_DEF_HS_SICH_Configuration_TDD384_tags_1[0]), /* 1 */
	asn_DEF_HS_SICH_Configuration_TDD384_tags_1,	/* Same as above */
	sizeof(asn_DEF_HS_SICH_Configuration_TDD384_tags_1)
		/sizeof(asn_DEF_HS_SICH_Configuration_TDD384_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_HS_SICH_Configuration_TDD384_1,
	4,	/* Elements count */
	&asn_SPC_HS_SICH_Configuration_TDD384_specs_1	/* Additional specs */
};

