/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Class-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MCCH-MessageType.h"

static asn_oer_constraints_t asn_OER_type_MCCH_MessageType_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_MCCH_MessageType_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_MCCH_MessageType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsAccessInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSAccessInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsAccessInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsCommonPTMRBInformation),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSCommonPTMRBInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsCommonPTMRBInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsCurrentCellPTMRBInformation),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSCurrentCellPTMRBInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsCurrentCellPTMRBInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsGeneralInformation),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSGeneralInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsGeneralInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsModifiedServicesInformation),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSModifiedServicesInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsModifiedServicesInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsNeighbouringCellPTMRBInformation),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSNeighbouringCellPTMRBInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsNeighbouringCellPTMRBInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.mbmsUnmodifiedServicesInformation),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMSUnmodifiedServicesInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsUnmodifiedServicesInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare9),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare9"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare8),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare8"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare7),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare7"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare6),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare6"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare5),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare5"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare4),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare3),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare2),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MCCH_MessageType, choice.spare1),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare1"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_MCCH_MessageType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbmsAccessInformation */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mbmsCommonPTMRBInformation */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* mbmsCurrentCellPTMRBInformation */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* mbmsGeneralInformation */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* mbmsModifiedServicesInformation */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* mbmsNeighbouringCellPTMRBInformation */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* mbmsUnmodifiedServicesInformation */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* spare9 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* spare8 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* spare7 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* spare6 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* spare5 */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* spare4 */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* spare3 */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 }, /* spare2 */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 15, 0, 0 } /* spare1 */
};
asn_CHOICE_specifics_t asn_SPC_MCCH_MessageType_specs_1 = {
	sizeof(struct MCCH_MessageType),
	offsetof(struct MCCH_MessageType, _asn_ctx),
	offsetof(struct MCCH_MessageType, present),
	sizeof(((struct MCCH_MessageType *)0)->present),
	asn_MAP_MCCH_MessageType_tag2el_1,
	16,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_MCCH_MessageType = {
	"MCCH-MessageType",
	"MCCH-MessageType",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_MCCH_MessageType_constr_1, &asn_PER_type_MCCH_MessageType_constr_1, CHOICE_constraint },
	asn_MBR_MCCH_MessageType_1,
	16,	/* Elements count */
	&asn_SPC_MCCH_MessageType_specs_1	/* Additional specs */
};
