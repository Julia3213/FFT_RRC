/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "Event1a-LCR-r4.h"

#include "ForbiddenAffectCellList-LCR-r4.h"
asn_TYPE_member_t asn_MBR_Event1a_LCR_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, triggeringCondition),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TriggeringCondition2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"triggeringCondition"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, reportingRange),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportingRange,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportingRange"
		},
	{ ATF_POINTER, 1, offsetof(struct Event1a_LCR_r4, forbiddenAffectCellList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ForbiddenAffectCellList_LCR_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"forbiddenAffectCellList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, w),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_W,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"w"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, reportDeactivationThreshold),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportDeactivationThreshold,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportDeactivationThreshold"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, reportingAmount),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportingAmount,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportingAmount"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event1a_LCR_r4, reportingInterval),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportingInterval,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportingInterval"
		},
};
static const int asn_MAP_Event1a_LCR_r4_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_Event1a_LCR_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Event1a_LCR_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* triggeringCondition */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* reportingRange */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* forbiddenAffectCellList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* w */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* reportDeactivationThreshold */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* reportingAmount */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* reportingInterval */
};
asn_SEQUENCE_specifics_t asn_SPC_Event1a_LCR_r4_specs_1 = {
	sizeof(struct Event1a_LCR_r4),
	offsetof(struct Event1a_LCR_r4, _asn_ctx),
	asn_MAP_Event1a_LCR_r4_tag2el_1,
	7,	/* Count of tags in the map */
	asn_MAP_Event1a_LCR_r4_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Event1a_LCR_r4 = {
	"Event1a-LCR-r4",
	"Event1a-LCR-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_Event1a_LCR_r4_tags_1,
	sizeof(asn_DEF_Event1a_LCR_r4_tags_1)
		/sizeof(asn_DEF_Event1a_LCR_r4_tags_1[0]), /* 1 */
	asn_DEF_Event1a_LCR_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_Event1a_LCR_r4_tags_1)
		/sizeof(asn_DEF_Event1a_LCR_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Event1a_LCR_r4_1,
	7,	/* Elements count */
	&asn_SPC_Event1a_LCR_r4_specs_1	/* Additional specs */
};

