/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-DPCH-InfoPerRL.h"

#include "SecondaryCPICH-Info.h"
#include "DL-CCTrChList.h"
#include "DL-CCTrChListToRemove.h"
static asn_oer_constraints_t asn_OER_type_DL_DPCH_InfoPerRL_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_DL_DPCH_InfoPerRL_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL__fdd, pCPICH_UsageForChannelEst),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PCPICH_UsageForChannelEst,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pCPICH-UsageForChannelEst"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL__fdd, dpch_FrameOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DPCH_FrameOffset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dpch-FrameOffset"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_DPCH_InfoPerRL__fdd, secondaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL__fdd, dl_ChannelisationCodeList),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_ChannelisationCodeList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-ChannelisationCodeList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL__fdd, tpc_CombinationIndex),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TPC_CombinationIndex,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tpc-CombinationIndex"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_DPCH_InfoPerRL__fdd, dummy),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SSDT_CellIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_DPCH_InfoPerRL__fdd, closedLoopTimingAdjMode),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ClosedLoopTimingAdjMode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"closedLoopTimingAdjMode"
		},
};
static const int asn_MAP_fdd_oms_2[] = { 2, 5, 6 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pCPICH-UsageForChannelEst */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dpch-FrameOffset */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* secondaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* dl-ChannelisationCodeList */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* tpc-CombinationIndex */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* dummy */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* closedLoopTimingAdjMode */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_2 = {
	sizeof(struct DL_DPCH_InfoPerRL__fdd),
	offsetof(struct DL_DPCH_InfoPerRL__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_2,
	7,	/* Count of tags in the map */
	asn_MAP_fdd_oms_2,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_2 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_2,
	sizeof(asn_DEF_fdd_tags_2)
		/sizeof(asn_DEF_fdd_tags_2[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_2,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_2)
		/sizeof(asn_DEF_fdd_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_2,
	7,	/* Elements count */
	&asn_SPC_fdd_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_10[] = {
	{ ATF_POINTER, 2, offsetof(struct DL_DPCH_InfoPerRL__tdd, dl_CCTrChListToEstablish),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CCTrChList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CCTrChListToEstablish"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_DPCH_InfoPerRL__tdd, dl_CCTrChListToRemove),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CCTrChListToRemove,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CCTrChListToRemove"
		},
};
static const int asn_MAP_tdd_oms_10[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_tdd_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-CCTrChListToEstablish */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-CCTrChListToRemove */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_10 = {
	sizeof(struct DL_DPCH_InfoPerRL__tdd),
	offsetof(struct DL_DPCH_InfoPerRL__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_10,
	2,	/* Count of tags in the map */
	asn_MAP_tdd_oms_10,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_10 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_10,
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_10,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_10,
	2,	/* Elements count */
	&asn_SPC_tdd_specs_10	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DL_DPCH_InfoPerRL_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_DPCH_InfoPerRL, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_DL_DPCH_InfoPerRL_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
asn_CHOICE_specifics_t asn_SPC_DL_DPCH_InfoPerRL_specs_1 = {
	sizeof(struct DL_DPCH_InfoPerRL),
	offsetof(struct DL_DPCH_InfoPerRL, _asn_ctx),
	offsetof(struct DL_DPCH_InfoPerRL, present),
	sizeof(((struct DL_DPCH_InfoPerRL *)0)->present),
	asn_MAP_DL_DPCH_InfoPerRL_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_DL_DPCH_InfoPerRL = {
	"DL-DPCH-InfoPerRL",
	"DL-DPCH-InfoPerRL",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_DL_DPCH_InfoPerRL_constr_1, &asn_PER_type_DL_DPCH_InfoPerRL_constr_1, CHOICE_constraint },
	asn_MBR_DL_DPCH_InfoPerRL_1,
	2,	/* Elements count */
	&asn_SPC_DL_DPCH_InfoPerRL_specs_1	/* Additional specs */
};

