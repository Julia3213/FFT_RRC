/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-NeighbouringCellSCCPCH-r6.h"

#include "MBMS-L1CombiningSchedule.h"
static asn_oer_constraints_t asn_OER_type_layer1Combining_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_layer1Combining_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining__fdd, softComb_TimingOffset),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_SoftComb_TimingOffset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"softComb-TimingOffset"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining__fdd, mbms_L1CombiningTransmTimeDiff),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_L1CombiningTransmTimeDiff,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-L1CombiningTransmTimeDiff"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining__fdd, mbms_L1CombiningSchedule),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_MBMS_L1CombiningSchedule,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-L1CombiningSchedule"
		},
};
static const int asn_MAP_fdd_oms_5[] = { 2 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* softComb-TimingOffset */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mbms-L1CombiningTransmTimeDiff */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* mbms-L1CombiningSchedule */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_5 = {
	sizeof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining__fdd),
	offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_5,
	3,	/* Count of tags in the map */
	asn_MAP_fdd_oms_5,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_5 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_5,
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_5,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_5,
	3,	/* Elements count */
	&asn_SPC_fdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_layer1Combining_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_layer1Combining_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_layer1Combining_specs_4 = {
	sizeof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining),
	offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining, _asn_ctx),
	offsetof(struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining, present),
	sizeof(((struct MBMS_NeighbouringCellSCCPCH_r6__layer1Combining *)0)->present),
	asn_MAP_layer1Combining_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_layer1Combining_4 = {
	"layer1Combining",
	"layer1Combining",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_layer1Combining_constr_4, &asn_PER_type_layer1Combining_constr_4, CHOICE_constraint },
	asn_MBR_layer1Combining_4,
	2,	/* Elements count */
	&asn_SPC_layer1Combining_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_MBMS_NeighbouringCellSCCPCH_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6, secondaryCCPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_CommonPhyChIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryCCPCH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6, secondaryCCPCHPwrOffsetDiff),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_SCCPCHPwrOffsetDiff,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryCCPCHPwrOffsetDiff"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6, layer1Combining),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_layer1Combining_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"layer1Combining"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_NeighbouringCellSCCPCH_r6, mbms_L23Configuration),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_MBMS_L23Configuration,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-L23Configuration"
		},
};
static const int asn_MAP_MBMS_NeighbouringCellSCCPCH_r6_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMS_NeighbouringCellSCCPCH_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* secondaryCCPCH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* secondaryCCPCHPwrOffsetDiff */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* layer1Combining */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* mbms-L23Configuration */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMS_NeighbouringCellSCCPCH_r6_specs_1 = {
	sizeof(struct MBMS_NeighbouringCellSCCPCH_r6),
	offsetof(struct MBMS_NeighbouringCellSCCPCH_r6, _asn_ctx),
	asn_MAP_MBMS_NeighbouringCellSCCPCH_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_MBMS_NeighbouringCellSCCPCH_r6_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_NeighbouringCellSCCPCH_r6 = {
	"MBMS-NeighbouringCellSCCPCH-r6",
	"MBMS-NeighbouringCellSCCPCH-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1,
	sizeof(asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1)
		/sizeof(asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1[0]), /* 1 */
	asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1)
		/sizeof(asn_DEF_MBMS_NeighbouringCellSCCPCH_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMS_NeighbouringCellSCCPCH_r6_1,
	4,	/* Elements count */
	&asn_SPC_MBMS_NeighbouringCellSCCPCH_r6_specs_1	/* Additional specs */
};

