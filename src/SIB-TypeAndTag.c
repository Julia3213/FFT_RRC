/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SIB-TypeAndTag.h"

static asn_oer_constraints_t asn_OER_type_SIB_TypeAndTag_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_SIB_TypeAndTag_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 5,  5,  0,  31 }	/* (0..31) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_SIB_TypeAndTag_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PLMN_ValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType2),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType3),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType4),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType5),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType5"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType6),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType6"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType7),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType7"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.dummy),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.dummy2),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.dummy3),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType11),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType12),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType13),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType13_1),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType13-1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType13_2),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType13-2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType13_3),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType13-3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType13_4),
		(ASN_TAG_CLASS_CONTEXT | (16 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType13-4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType14),
		(ASN_TAG_CLASS_CONTEXT | (17 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15),
		(ASN_TAG_CLASS_CONTEXT | (18 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType16),
		(ASN_TAG_CLASS_CONTEXT | (19 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PredefinedConfigIdentityAndValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType16"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType17),
		(ASN_TAG_CLASS_CONTEXT | (20 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType17"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15_1),
		(ASN_TAG_CLASS_CONTEXT | (21 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15-1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15_2),
		(ASN_TAG_CLASS_CONTEXT | (22 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIBOccurrenceIdentityAndValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15-2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15_3),
		(ASN_TAG_CLASS_CONTEXT | (23 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIBOccurrenceIdentityAndValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15-3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15_4),
		(ASN_TAG_CLASS_CONTEXT | (24 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15-4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType18),
		(ASN_TAG_CLASS_CONTEXT | (25 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType18"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType15_5),
		(ASN_TAG_CLASS_CONTEXT | (26 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType15-5"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.sysInfoType5bis),
		(ASN_TAG_CLASS_CONTEXT | (27 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellValueTag,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sysInfoType5bis"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.spare4),
		(ASN_TAG_CLASS_CONTEXT | (28 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.spare3),
		(ASN_TAG_CLASS_CONTEXT | (29 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.spare2),
		(ASN_TAG_CLASS_CONTEXT | (30 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SIB_TypeAndTag, choice.spare1),
		(ASN_TAG_CLASS_CONTEXT | (31 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare1"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_SIB_TypeAndTag_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sysInfoType1 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sysInfoType2 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sysInfoType3 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* sysInfoType4 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* sysInfoType5 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* sysInfoType6 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* sysInfoType7 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* dummy */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* dummy2 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* dummy3 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* sysInfoType11 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* sysInfoType12 */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* sysInfoType13 */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* sysInfoType13-1 */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 }, /* sysInfoType13-2 */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 15, 0, 0 }, /* sysInfoType13-3 */
    { (ASN_TAG_CLASS_CONTEXT | (16 << 2)), 16, 0, 0 }, /* sysInfoType13-4 */
    { (ASN_TAG_CLASS_CONTEXT | (17 << 2)), 17, 0, 0 }, /* sysInfoType14 */
    { (ASN_TAG_CLASS_CONTEXT | (18 << 2)), 18, 0, 0 }, /* sysInfoType15 */
    { (ASN_TAG_CLASS_CONTEXT | (19 << 2)), 19, 0, 0 }, /* sysInfoType16 */
    { (ASN_TAG_CLASS_CONTEXT | (20 << 2)), 20, 0, 0 }, /* sysInfoType17 */
    { (ASN_TAG_CLASS_CONTEXT | (21 << 2)), 21, 0, 0 }, /* sysInfoType15-1 */
    { (ASN_TAG_CLASS_CONTEXT | (22 << 2)), 22, 0, 0 }, /* sysInfoType15-2 */
    { (ASN_TAG_CLASS_CONTEXT | (23 << 2)), 23, 0, 0 }, /* sysInfoType15-3 */
    { (ASN_TAG_CLASS_CONTEXT | (24 << 2)), 24, 0, 0 }, /* sysInfoType15-4 */
    { (ASN_TAG_CLASS_CONTEXT | (25 << 2)), 25, 0, 0 }, /* sysInfoType18 */
    { (ASN_TAG_CLASS_CONTEXT | (26 << 2)), 26, 0, 0 }, /* sysInfoType15-5 */
    { (ASN_TAG_CLASS_CONTEXT | (27 << 2)), 27, 0, 0 }, /* sysInfoType5bis */
    { (ASN_TAG_CLASS_CONTEXT | (28 << 2)), 28, 0, 0 }, /* spare4 */
    { (ASN_TAG_CLASS_CONTEXT | (29 << 2)), 29, 0, 0 }, /* spare3 */
    { (ASN_TAG_CLASS_CONTEXT | (30 << 2)), 30, 0, 0 }, /* spare2 */
    { (ASN_TAG_CLASS_CONTEXT | (31 << 2)), 31, 0, 0 } /* spare1 */
};
asn_CHOICE_specifics_t asn_SPC_SIB_TypeAndTag_specs_1 = {
	sizeof(struct SIB_TypeAndTag),
	offsetof(struct SIB_TypeAndTag, _asn_ctx),
	offsetof(struct SIB_TypeAndTag, present),
	sizeof(((struct SIB_TypeAndTag *)0)->present),
	asn_MAP_SIB_TypeAndTag_tag2el_1,
	32,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_SIB_TypeAndTag = {
	"SIB-TypeAndTag",
	"SIB-TypeAndTag",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_SIB_TypeAndTag_constr_1, &asn_PER_type_SIB_TypeAndTag_constr_1, CHOICE_constraint },
	asn_MBR_SIB_TypeAndTag_1,
	32,	/* Elements count */
	&asn_SPC_SIB_TypeAndTag_specs_1	/* Additional specs */
};

