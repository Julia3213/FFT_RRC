/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "AssistanceDataDelivery.h"

static asn_oer_constraints_t asn_OER_type_AssistanceDataDelivery_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_AssistanceDataDelivery_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_10 = {
	sizeof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_10 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_10,
	sizeof(asn_DEF_nonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_10[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_10,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v4b0NonCriticalExtensions_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions, assistanceDataDelivery_v4b0ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AssistanceDataDelivery_v4b0ext_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"assistanceDataDelivery-v4b0ext"
		},
	{ ATF_POINTER, 1, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_v4b0NonCriticalExtensions_oms_8[] = { 1 };
static const ber_tlv_tag_t asn_DEF_v4b0NonCriticalExtensions_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_v4b0NonCriticalExtensions_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* assistanceDataDelivery-v4b0ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_v4b0NonCriticalExtensions_specs_8 = {
	sizeof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions),
	offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions, _asn_ctx),
	asn_MAP_v4b0NonCriticalExtensions_tag2el_8,
	2,	/* Count of tags in the map */
	asn_MAP_v4b0NonCriticalExtensions_oms_8,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v4b0NonCriticalExtensions_8 = {
	"v4b0NonCriticalExtensions",
	"v4b0NonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_v4b0NonCriticalExtensions_tags_8,
	sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_8[0]) - 1, /* 1 */
	asn_DEF_v4b0NonCriticalExtensions_tags_8,	/* Same as above */
	sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_8[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_v4b0NonCriticalExtensions_8,
	2,	/* Elements count */
	&asn_SPC_v4b0NonCriticalExtensions_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_laterNonCriticalExtensions_6[] = {
	{ ATF_POINTER, 2, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions, assistanceDataDelivery_r3_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"assistanceDataDelivery-r3-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions, v4b0NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v4b0NonCriticalExtensions_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"v4b0NonCriticalExtensions"
		},
};
static const int asn_MAP_laterNonCriticalExtensions_oms_6[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_laterNonCriticalExtensions_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_laterNonCriticalExtensions_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* assistanceDataDelivery-r3-add-ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v4b0NonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_laterNonCriticalExtensions_specs_6 = {
	sizeof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions),
	offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions, _asn_ctx),
	asn_MAP_laterNonCriticalExtensions_tag2el_6,
	2,	/* Count of tags in the map */
	asn_MAP_laterNonCriticalExtensions_oms_6,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_laterNonCriticalExtensions_6 = {
	"laterNonCriticalExtensions",
	"laterNonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_laterNonCriticalExtensions_tags_6,
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_6[0]) - 1, /* 1 */
	asn_DEF_laterNonCriticalExtensions_tags_6,	/* Same as above */
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_6[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_laterNonCriticalExtensions_6,
	2,	/* Elements count */
	&asn_SPC_laterNonCriticalExtensions_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v3a0NonCriticalExtensions_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions, assistanceDataDelivery_v3a0ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AssistanceDataDelivery_v3a0ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"assistanceDataDelivery-v3a0ext"
		},
	{ ATF_POINTER, 1, offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions, laterNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_laterNonCriticalExtensions_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"laterNonCriticalExtensions"
		},
};
static const int asn_MAP_v3a0NonCriticalExtensions_oms_4[] = { 1 };
static const ber_tlv_tag_t asn_DEF_v3a0NonCriticalExtensions_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_v3a0NonCriticalExtensions_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* assistanceDataDelivery-v3a0ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* laterNonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_v3a0NonCriticalExtensions_specs_4 = {
	sizeof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions),
	offsetof(struct AssistanceDataDelivery__r3__v3a0NonCriticalExtensions, _asn_ctx),
	asn_MAP_v3a0NonCriticalExtensions_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_v3a0NonCriticalExtensions_oms_4,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v3a0NonCriticalExtensions_4 = {
	"v3a0NonCriticalExtensions",
	"v3a0NonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_v3a0NonCriticalExtensions_tags_4,
	sizeof(asn_DEF_v3a0NonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_v3a0NonCriticalExtensions_tags_4[0]) - 1, /* 1 */
	asn_DEF_v3a0NonCriticalExtensions_tags_4,	/* Same as above */
	sizeof(asn_DEF_v3a0NonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_v3a0NonCriticalExtensions_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_v3a0NonCriticalExtensions_4,
	2,	/* Elements count */
	&asn_SPC_v3a0NonCriticalExtensions_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r3_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery__r3, assistanceDataDelivery_r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AssistanceDataDelivery_r3_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"assistanceDataDelivery-r3"
		},
	{ ATF_POINTER, 1, offsetof(struct AssistanceDataDelivery__r3, v3a0NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v3a0NonCriticalExtensions_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"v3a0NonCriticalExtensions"
		},
};
static const int asn_MAP_r3_oms_2[] = { 1 };
static const ber_tlv_tag_t asn_DEF_r3_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_r3_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* assistanceDataDelivery-r3 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v3a0NonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_r3_specs_2 = {
	sizeof(struct AssistanceDataDelivery__r3),
	offsetof(struct AssistanceDataDelivery__r3, _asn_ctx),
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

static const ber_tlv_tag_t asn_DEF_criticalExtensions_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_criticalExtensions_specs_13 = {
	sizeof(struct AssistanceDataDelivery__later_than_r3__criticalExtensions),
	offsetof(struct AssistanceDataDelivery__later_than_r3__criticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_13 = {
	"criticalExtensions",
	"criticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_criticalExtensions_tags_13,
	sizeof(asn_DEF_criticalExtensions_tags_13)
		/sizeof(asn_DEF_criticalExtensions_tags_13[0]) - 1, /* 1 */
	asn_DEF_criticalExtensions_tags_13,	/* Same as above */
	sizeof(asn_DEF_criticalExtensions_tags_13)
		/sizeof(asn_DEF_criticalExtensions_tags_13[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_criticalExtensions_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_later_than_r3_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery__later_than_r3, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-TransactionIdentifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery__later_than_r3, criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_criticalExtensions_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"criticalExtensions"
		},
};
static const ber_tlv_tag_t asn_DEF_later_than_r3_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_later_than_r3_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_later_than_r3_specs_11 = {
	sizeof(struct AssistanceDataDelivery__later_than_r3),
	offsetof(struct AssistanceDataDelivery__later_than_r3, _asn_ctx),
	asn_MAP_later_than_r3_tag2el_11,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_later_than_r3_11 = {
	"later-than-r3",
	"later-than-r3",
	&asn_OP_SEQUENCE,
	asn_DEF_later_than_r3_tags_11,
	sizeof(asn_DEF_later_than_r3_tags_11)
		/sizeof(asn_DEF_later_than_r3_tags_11[0]) - 1, /* 1 */
	asn_DEF_later_than_r3_tags_11,	/* Same as above */
	sizeof(asn_DEF_later_than_r3_tags_11)
		/sizeof(asn_DEF_later_than_r3_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_later_than_r3_11,
	2,	/* Elements count */
	&asn_SPC_later_than_r3_specs_11	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_AssistanceDataDelivery_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery, choice.r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r3_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"r3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AssistanceDataDelivery, choice.later_than_r3),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_later_than_r3_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"later-than-r3"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_AssistanceDataDelivery_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r3 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* later-than-r3 */
};
asn_CHOICE_specifics_t asn_SPC_AssistanceDataDelivery_specs_1 = {
	sizeof(struct AssistanceDataDelivery),
	offsetof(struct AssistanceDataDelivery, _asn_ctx),
	offsetof(struct AssistanceDataDelivery, present),
	sizeof(((struct AssistanceDataDelivery *)0)->present),
	asn_MAP_AssistanceDataDelivery_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_AssistanceDataDelivery = {
	"AssistanceDataDelivery",
	"AssistanceDataDelivery",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_AssistanceDataDelivery_constr_1, &asn_PER_type_AssistanceDataDelivery_constr_1, CHOICE_constraint },
	asn_MBR_AssistanceDataDelivery_1,
	2,	/* Elements count */
	&asn_SPC_AssistanceDataDelivery_specs_1	/* Additional specs */
};

