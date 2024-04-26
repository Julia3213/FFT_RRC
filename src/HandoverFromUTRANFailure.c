/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "HandoverFromUTRANFailure.h"

#include "InterRAT-HO-FailureCause.h"
static asn_oer_constraints_t asn_OER_type_interRATMessage_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_interRATMessage_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_gsm_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure__interRATMessage__gsm, gsm_MessageList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GSM_MessageList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gsm-MessageList"
		},
};
static const ber_tlv_tag_t asn_DEF_gsm_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_gsm_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* gsm-MessageList */
};
static asn_SEQUENCE_specifics_t asn_SPC_gsm_specs_5 = {
	sizeof(struct HandoverFromUTRANFailure__interRATMessage__gsm),
	offsetof(struct HandoverFromUTRANFailure__interRATMessage__gsm, _asn_ctx),
	asn_MAP_gsm_tag2el_5,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_gsm_5 = {
	"gsm",
	"gsm",
	&asn_OP_SEQUENCE,
	asn_DEF_gsm_tags_5,
	sizeof(asn_DEF_gsm_tags_5)
		/sizeof(asn_DEF_gsm_tags_5[0]) - 1, /* 1 */
	asn_DEF_gsm_tags_5,	/* Same as above */
	sizeof(asn_DEF_gsm_tags_5)
		/sizeof(asn_DEF_gsm_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_gsm_5,
	1,	/* Elements count */
	&asn_SPC_gsm_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_cdma2000_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure__interRATMessage__cdma2000, cdma2000_MessageList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CDMA2000_MessageList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cdma2000-MessageList"
		},
};
static const ber_tlv_tag_t asn_DEF_cdma2000_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_cdma2000_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* cdma2000-MessageList */
};
static asn_SEQUENCE_specifics_t asn_SPC_cdma2000_specs_7 = {
	sizeof(struct HandoverFromUTRANFailure__interRATMessage__cdma2000),
	offsetof(struct HandoverFromUTRANFailure__interRATMessage__cdma2000, _asn_ctx),
	asn_MAP_cdma2000_tag2el_7,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_cdma2000_7 = {
	"cdma2000",
	"cdma2000",
	&asn_OP_SEQUENCE,
	asn_DEF_cdma2000_tags_7,
	sizeof(asn_DEF_cdma2000_tags_7)
		/sizeof(asn_DEF_cdma2000_tags_7[0]) - 1, /* 1 */
	asn_DEF_cdma2000_tags_7,	/* Same as above */
	sizeof(asn_DEF_cdma2000_tags_7)
		/sizeof(asn_DEF_cdma2000_tags_7[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_cdma2000_7,
	1,	/* Elements count */
	&asn_SPC_cdma2000_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_interRATMessage_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure__interRATMessage, choice.gsm),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_gsm_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gsm"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure__interRATMessage, choice.cdma2000),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_cdma2000_7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cdma2000"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_interRATMessage_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gsm */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* cdma2000 */
};
static asn_CHOICE_specifics_t asn_SPC_interRATMessage_specs_4 = {
	sizeof(struct HandoverFromUTRANFailure__interRATMessage),
	offsetof(struct HandoverFromUTRANFailure__interRATMessage, _asn_ctx),
	offsetof(struct HandoverFromUTRANFailure__interRATMessage, present),
	sizeof(((struct HandoverFromUTRANFailure__interRATMessage *)0)->present),
	asn_MAP_interRATMessage_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_interRATMessage_4 = {
	"interRATMessage",
	"interRATMessage",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_interRATMessage_constr_4, &asn_PER_type_interRATMessage_constr_4, CHOICE_constraint },
	asn_MBR_interRATMessage_4,
	2,	/* Elements count */
	&asn_SPC_interRATMessage_specs_4	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_13 = {
	sizeof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_13 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_13,
	sizeof(asn_DEF_nonCriticalExtensions_tags_13)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_13[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_13,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_13)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_13[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v590NonCriticalExtensions_11[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions, handoverFromUTRANFailure_v590ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverFromUtranFailure_v590ext_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"handoverFromUTRANFailure-v590ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_v590NonCriticalExtensions_oms_11[] = { 1 };
static const ber_tlv_tag_t asn_DEF_v590NonCriticalExtensions_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_v590NonCriticalExtensions_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverFromUTRANFailure-v590ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_v590NonCriticalExtensions_specs_11 = {
	sizeof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions),
	offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions__v590NonCriticalExtensions, _asn_ctx),
	asn_MAP_v590NonCriticalExtensions_tag2el_11,
	2,	/* Count of tags in the map */
	asn_MAP_v590NonCriticalExtensions_oms_11,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v590NonCriticalExtensions_11 = {
	"v590NonCriticalExtensions",
	"v590NonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_v590NonCriticalExtensions_tags_11,
	sizeof(asn_DEF_v590NonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_v590NonCriticalExtensions_tags_11[0]) - 1, /* 1 */
	asn_DEF_v590NonCriticalExtensions_tags_11,	/* Same as above */
	sizeof(asn_DEF_v590NonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_v590NonCriticalExtensions_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_v590NonCriticalExtensions_11,
	2,	/* Elements count */
	&asn_SPC_v590NonCriticalExtensions_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_laterNonCriticalExtensions_9[] = {
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions, handoverFromUTRANFailure_r3_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"handoverFromUTRANFailure-r3-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions, v590NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v590NonCriticalExtensions_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"v590NonCriticalExtensions"
		},
};
static const int asn_MAP_laterNonCriticalExtensions_oms_9[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_laterNonCriticalExtensions_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_laterNonCriticalExtensions_tag2el_9[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverFromUTRANFailure-r3-add-ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v590NonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_laterNonCriticalExtensions_specs_9 = {
	sizeof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions),
	offsetof(struct HandoverFromUTRANFailure__laterNonCriticalExtensions, _asn_ctx),
	asn_MAP_laterNonCriticalExtensions_tag2el_9,
	2,	/* Count of tags in the map */
	asn_MAP_laterNonCriticalExtensions_oms_9,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_laterNonCriticalExtensions_9 = {
	"laterNonCriticalExtensions",
	"laterNonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_laterNonCriticalExtensions_tags_9,
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_9)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_9[0]) - 1, /* 1 */
	asn_DEF_laterNonCriticalExtensions_tags_9,	/* Same as above */
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_9)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_9[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_laterNonCriticalExtensions_9,
	2,	/* Elements count */
	&asn_SPC_laterNonCriticalExtensions_specs_9	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_HandoverFromUTRANFailure_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANFailure, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-TransactionIdentifier"
		},
	{ ATF_POINTER, 3, offsetof(struct HandoverFromUTRANFailure, interRAT_HO_FailureCause),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_InterRAT_HO_FailureCause,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interRAT-HO-FailureCause"
		},
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANFailure, interRATMessage),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_interRATMessage_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interRATMessage"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANFailure, laterNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_laterNonCriticalExtensions_9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"laterNonCriticalExtensions"
		},
};
static const int asn_MAP_HandoverFromUTRANFailure_oms_1[] = { 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_HandoverFromUTRANFailure_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HandoverFromUTRANFailure_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interRAT-HO-FailureCause */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* interRATMessage */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* laterNonCriticalExtensions */
};
asn_SEQUENCE_specifics_t asn_SPC_HandoverFromUTRANFailure_specs_1 = {
	sizeof(struct HandoverFromUTRANFailure),
	offsetof(struct HandoverFromUTRANFailure, _asn_ctx),
	asn_MAP_HandoverFromUTRANFailure_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_HandoverFromUTRANFailure_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANFailure = {
	"HandoverFromUTRANFailure",
	"HandoverFromUTRANFailure",
	&asn_OP_SEQUENCE,
	asn_DEF_HandoverFromUTRANFailure_tags_1,
	sizeof(asn_DEF_HandoverFromUTRANFailure_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANFailure_tags_1[0]), /* 1 */
	asn_DEF_HandoverFromUTRANFailure_tags_1,	/* Same as above */
	sizeof(asn_DEF_HandoverFromUTRANFailure_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANFailure_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_HandoverFromUTRANFailure_1,
	4,	/* Elements count */
	&asn_SPC_HandoverFromUTRANFailure_specs_1	/* Additional specs */
};
