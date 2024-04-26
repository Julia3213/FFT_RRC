/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SignallingConnectionRelease.h"

static asn_oer_constraints_t asn_OER_type_SignallingConnectionRelease_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_SignallingConnectionRelease_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_6 = {
	sizeof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_6 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_6,
	sizeof(asn_DEF_nonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_6[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_6,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_laterNonCriticalExtensions_4[] = {
	{ ATF_POINTER, 2, offsetof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions, signallingConnectionRelease_r3_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"signallingConnectionRelease-r3-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_laterNonCriticalExtensions_oms_4[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_laterNonCriticalExtensions_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_laterNonCriticalExtensions_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* signallingConnectionRelease-r3-add-ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_laterNonCriticalExtensions_specs_4 = {
	sizeof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions),
	offsetof(struct SignallingConnectionRelease__r3__laterNonCriticalExtensions, _asn_ctx),
	asn_MAP_laterNonCriticalExtensions_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_laterNonCriticalExtensions_oms_4,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_laterNonCriticalExtensions_4 = {
	"laterNonCriticalExtensions",
	"laterNonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_laterNonCriticalExtensions_tags_4,
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_4[0]) - 1, /* 1 */
	asn_DEF_laterNonCriticalExtensions_tags_4,	/* Same as above */
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_laterNonCriticalExtensions_4,
	2,	/* Elements count */
	&asn_SPC_laterNonCriticalExtensions_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r3_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SignallingConnectionRelease__r3, signallingConnectionRelease_r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SignallingConnectionRelease_r3_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"signallingConnectionRelease-r3"
		},
	{ ATF_POINTER, 1, offsetof(struct SignallingConnectionRelease__r3, laterNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_laterNonCriticalExtensions_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"laterNonCriticalExtensions"
		},
};
static const int asn_MAP_r3_oms_2[] = { 1 };
static const ber_tlv_tag_t asn_DEF_r3_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_r3_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* signallingConnectionRelease-r3 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* laterNonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_r3_specs_2 = {
	sizeof(struct SignallingConnectionRelease__r3),
	offsetof(struct SignallingConnectionRelease__r3, _asn_ctx),
	asn_MAP_r3_tag2el_2,
	2,	/* Count of tags in the map */
	asn_MAP_r3_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r3_2 = {
	"r3",
	"r3",
	&asn_OP_SEQUENCE,
	asn_DEF_r3_tags_2,
	sizeof(asn_DEF_r3_tags_2)
		/sizeof(asn_DEF_r3_tags_2[0]) - 1, /* 1 */
	asn_DEF_r3_tags_2,	/* Same as above */
	sizeof(asn_DEF_r3_tags_2)
		/sizeof(asn_DEF_r3_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_r3_2,
	2,	/* Elements count */
	&asn_SPC_r3_specs_2	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_criticalExtensions_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_criticalExtensions_specs_9 = {
	sizeof(struct SignallingConnectionRelease__later_than_r3__criticalExtensions),
	offsetof(struct SignallingConnectionRelease__later_than_r3__criticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_9 = {
	"criticalExtensions",
	"criticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_criticalExtensions_tags_9,
	sizeof(asn_DEF_criticalExtensions_tags_9)
		/sizeof(asn_DEF_criticalExtensions_tags_9[0]) - 1, /* 1 */
	asn_DEF_criticalExtensions_tags_9,	/* Same as above */
	sizeof(asn_DEF_criticalExtensions_tags_9)
		/sizeof(asn_DEF_criticalExtensions_tags_9[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_criticalExtensions_specs_9	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_later_than_r3_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SignallingConnectionRelease__later_than_r3, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-TransactionIdentifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SignallingConnectionRelease__later_than_r3, criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_criticalExtensions_9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"criticalExtensions"
		},
};
static const ber_tlv_tag_t asn_DEF_later_than_r3_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_later_than_r3_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_later_than_r3_specs_7 = {
	sizeof(struct SignallingConnectionRelease__later_than_r3),
	offsetof(struct SignallingConnectionRelease__later_than_r3, _asn_ctx),
	asn_MAP_later_than_r3_tag2el_7,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_later_than_r3_7 = {
	"later-than-r3",
	"later-than-r3",
	&asn_OP_SEQUENCE,
	asn_DEF_later_than_r3_tags_7,
	sizeof(asn_DEF_later_than_r3_tags_7)
		/sizeof(asn_DEF_later_than_r3_tags_7[0]) - 1, /* 1 */
	asn_DEF_later_than_r3_tags_7,	/* Same as above */
	sizeof(asn_DEF_later_than_r3_tags_7)
		/sizeof(asn_DEF_later_than_r3_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_later_than_r3_7,
	2,	/* Elements count */
	&asn_SPC_later_than_r3_specs_7	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SignallingConnectionRelease_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SignallingConnectionRelease, choice.r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r3_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"r3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SignallingConnectionRelease, choice.later_than_r3),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_later_than_r3_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"later-than-r3"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_SignallingConnectionRelease_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r3 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* later-than-r3 */
};
asn_CHOICE_specifics_t asn_SPC_SignallingConnectionRelease_specs_1 = {
	sizeof(struct SignallingConnectionRelease),
	offsetof(struct SignallingConnectionRelease, _asn_ctx),
	offsetof(struct SignallingConnectionRelease, present),
	sizeof(((struct SignallingConnectionRelease *)0)->present),
	asn_MAP_SignallingConnectionRelease_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_SignallingConnectionRelease = {
	"SignallingConnectionRelease",
	"SignallingConnectionRelease",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_SignallingConnectionRelease_constr_1, &asn_PER_type_SignallingConnectionRelease_constr_1, CHOICE_constraint },
	asn_MBR_SignallingConnectionRelease_1,
	2,	/* Elements count */
	&asn_SPC_SignallingConnectionRelease_specs_1	/* Additional specs */
};
