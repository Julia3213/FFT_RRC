/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TransportChannelReconfigurationComplete.h"

#include "IntegrityProtActivationInfo.h"
#include "RB-ActivationTimeInfoList.h"
#include "UL-CounterSynchronisationInfo.h"
static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_12 = {
	sizeof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_12 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_12,
	sizeof(asn_DEF_nonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_12[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_12,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_12[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v7xyNonCriticalExtensions_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions, transportChannelReconfigurationComplete_v7xyext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelReconfigurationComplete_v7xyext_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transportChannelReconfigurationComplete-v7xyext"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_v7xyNonCriticalExtensions_oms_10[] = { 1 };
static const ber_tlv_tag_t asn_DEF_v7xyNonCriticalExtensions_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_v7xyNonCriticalExtensions_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transportChannelReconfigurationComplete-v7xyext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_v7xyNonCriticalExtensions_specs_10 = {
	sizeof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions),
	offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions__v7xyNonCriticalExtensions, _asn_ctx),
	asn_MAP_v7xyNonCriticalExtensions_tag2el_10,
	2,	/* Count of tags in the map */
	asn_MAP_v7xyNonCriticalExtensions_oms_10,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v7xyNonCriticalExtensions_10 = {
	"v7xyNonCriticalExtensions",
	"v7xyNonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_v7xyNonCriticalExtensions_tags_10,
	sizeof(asn_DEF_v7xyNonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_v7xyNonCriticalExtensions_tags_10[0]) - 1, /* 1 */
	asn_DEF_v7xyNonCriticalExtensions_tags_10,	/* Same as above */
	sizeof(asn_DEF_v7xyNonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_v7xyNonCriticalExtensions_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_v7xyNonCriticalExtensions_10,
	2,	/* Elements count */
	&asn_SPC_v7xyNonCriticalExtensions_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_laterNonCriticalExtensions_8[] = {
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions, transportChannelReconfigurationComplete_r3_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transportChannelReconfigurationComplete-r3-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions, v7xyNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v7xyNonCriticalExtensions_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"v7xyNonCriticalExtensions"
		},
};
static const int asn_MAP_laterNonCriticalExtensions_oms_8[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_laterNonCriticalExtensions_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_laterNonCriticalExtensions_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transportChannelReconfigurationComplete-r3-add-ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v7xyNonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_laterNonCriticalExtensions_specs_8 = {
	sizeof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions),
	offsetof(struct TransportChannelReconfigurationComplete__laterNonCriticalExtensions, _asn_ctx),
	asn_MAP_laterNonCriticalExtensions_tag2el_8,
	2,	/* Count of tags in the map */
	asn_MAP_laterNonCriticalExtensions_oms_8,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_laterNonCriticalExtensions_8 = {
	"laterNonCriticalExtensions",
	"laterNonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_laterNonCriticalExtensions_tags_8,
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_8[0]) - 1, /* 1 */
	asn_DEF_laterNonCriticalExtensions_tags_8,	/* Same as above */
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_8[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_laterNonCriticalExtensions_8,
	2,	/* Elements count */
	&asn_SPC_laterNonCriticalExtensions_specs_8	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_TransportChannelReconfigurationComplete_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TransportChannelReconfigurationComplete, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-TransactionIdentifier"
		},
	{ ATF_POINTER, 6, offsetof(struct TransportChannelReconfigurationComplete, ul_IntegProtActivationInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtActivationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-IntegProtActivationInfo"
		},
	{ ATF_POINTER, 5, offsetof(struct TransportChannelReconfigurationComplete, ul_TimingAdvance),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_TimingAdvance,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-TimingAdvance"
		},
	{ ATF_POINTER, 4, offsetof(struct TransportChannelReconfigurationComplete, count_C_ActivationTime),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"count-C-ActivationTime"
		},
	{ ATF_POINTER, 3, offsetof(struct TransportChannelReconfigurationComplete, dummy),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_ActivationTimeInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
	{ ATF_POINTER, 2, offsetof(struct TransportChannelReconfigurationComplete, ul_CounterSynchronisationInfo),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_CounterSynchronisationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-CounterSynchronisationInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct TransportChannelReconfigurationComplete, laterNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		0,
		&asn_DEF_laterNonCriticalExtensions_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"laterNonCriticalExtensions"
		},
};
static const int asn_MAP_TransportChannelReconfigurationComplete_oms_1[] = { 1, 2, 3, 4, 5, 6 };
static const ber_tlv_tag_t asn_DEF_TransportChannelReconfigurationComplete_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TransportChannelReconfigurationComplete_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ul-IntegProtActivationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ul-TimingAdvance */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* count-C-ActivationTime */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* dummy */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* ul-CounterSynchronisationInfo */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* laterNonCriticalExtensions */
};
asn_SEQUENCE_specifics_t asn_SPC_TransportChannelReconfigurationComplete_specs_1 = {
	sizeof(struct TransportChannelReconfigurationComplete),
	offsetof(struct TransportChannelReconfigurationComplete, _asn_ctx),
	asn_MAP_TransportChannelReconfigurationComplete_tag2el_1,
	7,	/* Count of tags in the map */
	asn_MAP_TransportChannelReconfigurationComplete_oms_1,	/* Optional members */
	6, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_TransportChannelReconfigurationComplete = {
	"TransportChannelReconfigurationComplete",
	"TransportChannelReconfigurationComplete",
	&asn_OP_SEQUENCE,
	asn_DEF_TransportChannelReconfigurationComplete_tags_1,
	sizeof(asn_DEF_TransportChannelReconfigurationComplete_tags_1)
		/sizeof(asn_DEF_TransportChannelReconfigurationComplete_tags_1[0]), /* 1 */
	asn_DEF_TransportChannelReconfigurationComplete_tags_1,	/* Same as above */
	sizeof(asn_DEF_TransportChannelReconfigurationComplete_tags_1)
		/sizeof(asn_DEF_TransportChannelReconfigurationComplete_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_TransportChannelReconfigurationComplete_1,
	7,	/* Elements count */
	&asn_SPC_TransportChannelReconfigurationComplete_specs_1	/* Additional specs */
};

