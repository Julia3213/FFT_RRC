/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "Event2f.h"

#include "ReportingCellStatus.h"
asn_TYPE_member_t asn_MBR_Event2f_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Event2f, usedFreqThreshold),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Threshold,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"usedFreqThreshold"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2f, usedFreqW),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_W,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"usedFreqW"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2f, hysteresis),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HysteresisInterFreq,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"hysteresis"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2f, timeToTrigger),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeToTrigger"
		},
	{ ATF_POINTER, 1, offsetof(struct Event2f, reportingCellStatus),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ReportingCellStatus,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportingCellStatus"
		},
};
static const int asn_MAP_Event2f_oms_1[] = { 4 };
static const ber_tlv_tag_t asn_DEF_Event2f_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Event2f_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* usedFreqThreshold */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* usedFreqW */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* hysteresis */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* timeToTrigger */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* reportingCellStatus */
};
asn_SEQUENCE_specifics_t asn_SPC_Event2f_specs_1 = {
	sizeof(struct Event2f),
	offsetof(struct Event2f, _asn_ctx),
	asn_MAP_Event2f_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_Event2f_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Event2f = {
	"Event2f",
	"Event2f",
	&asn_OP_SEQUENCE,
	asn_DEF_Event2f_tags_1,
	sizeof(asn_DEF_Event2f_tags_1)
		/sizeof(asn_DEF_Event2f_tags_1[0]), /* 1 */
	asn_DEF_Event2f_tags_1,	/* Same as above */
	sizeof(asn_DEF_Event2f_tags_1)
		/sizeof(asn_DEF_Event2f_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Event2f_1,
	5,	/* Elements count */
	&asn_SPC_Event2f_specs_1	/* Additional specs */
};

