/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CellInfoSI-ECN0.h"

#include "ReferenceTimeDifferenceToCell.h"
#include "CellSelectReselectInfoSIB-11-12-ECN0.h"
#include "PrimaryCPICH-Info.h"
#include "TimeslotInfoList.h"
static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static int asn_DFL_2_cmp_0(const void *sptr) {
	const CellIndividualOffset_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_2_set_0(void **sptr) {
	CellIndividualOffset_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static asn_TYPE_member_t asn_MBR_fdd_5[] = {
	{ ATF_POINTER, 2, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd, primaryCPICH_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_TX_Power,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-TX-Power"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd, readSFN_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"readSFN-Indicator"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd, tx_DiversityIndicator),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tx-DiversityIndicator"
		},
};
static const int asn_MAP_fdd_oms_5[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_fdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* primaryCPICH-TX-Power */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* readSFN-Indicator */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* tx-DiversityIndicator */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_5 = {
	sizeof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd),
	offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_5,
	4,	/* Count of tags in the map */
	asn_MAP_fdd_oms_5,	/* Optional members */
	2, 0,	/* Root/Additions */
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
	4,	/* Elements count */
	&asn_SPC_fdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd, primaryCCPCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PrimaryCCPCH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCCPCH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd, primaryCCPCH_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCCPCH_TX_Power,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCCPCH-TX-Power"
		},
	{ ATF_POINTER, 1, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd, timeslotInfoList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslotInfoList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd, readSFN_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"readSFN-Indicator"
		},
};
static const int asn_MAP_tdd_oms_10[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_tdd_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCCPCH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* primaryCCPCH-TX-Power */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timeslotInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* readSFN-Indicator */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_10 = {
	sizeof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd),
	offsetof(struct CellInfoSI_ECN0__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_10,
	4,	/* Count of tags in the map */
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
	4,	/* Elements count */
	&asn_SPC_tdd_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_4 = {
	sizeof(struct CellInfoSI_ECN0__modeSpecificInfo),
	offsetof(struct CellInfoSI_ECN0__modeSpecificInfo, _asn_ctx),
	offsetof(struct CellInfoSI_ECN0__modeSpecificInfo, present),
	sizeof(((struct CellInfoSI_ECN0__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_4 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_4, &asn_PER_type_modeSpecificInfo_constr_4, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_4,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_CellInfoSI_ECN0_1[] = {
	{ ATF_NOFLAGS, 2, offsetof(struct CellInfoSI_ECN0, cellIndividualOffset),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellIndividualOffset,
		0,
		{ 0, 0, 0 },
		&asn_DFL_2_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_2_set_0,	/* Set DEFAULT 0 */
		"cellIndividualOffset"
		},
	{ ATF_POINTER, 1, offsetof(struct CellInfoSI_ECN0, referenceTimeDifferenceToCell),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ReferenceTimeDifferenceToCell,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"referenceTimeDifferenceToCell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellInfoSI_ECN0, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct CellInfoSI_ECN0, cellSelectionReselectionInfo),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellSelectReselectInfoSIB_11_12_ECN0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellSelectionReselectionInfo"
		},
};
static const int asn_MAP_CellInfoSI_ECN0_oms_1[] = { 0, 1, 3 };
static const ber_tlv_tag_t asn_DEF_CellInfoSI_ECN0_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CellInfoSI_ECN0_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellIndividualOffset */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* referenceTimeDifferenceToCell */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* modeSpecificInfo */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* cellSelectionReselectionInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_CellInfoSI_ECN0_specs_1 = {
	sizeof(struct CellInfoSI_ECN0),
	offsetof(struct CellInfoSI_ECN0, _asn_ctx),
	asn_MAP_CellInfoSI_ECN0_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_CellInfoSI_ECN0_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CellInfoSI_ECN0 = {
	"CellInfoSI-ECN0",
	"CellInfoSI-ECN0",
	&asn_OP_SEQUENCE,
	asn_DEF_CellInfoSI_ECN0_tags_1,
	sizeof(asn_DEF_CellInfoSI_ECN0_tags_1)
		/sizeof(asn_DEF_CellInfoSI_ECN0_tags_1[0]), /* 1 */
	asn_DEF_CellInfoSI_ECN0_tags_1,	/* Same as above */
	sizeof(asn_DEF_CellInfoSI_ECN0_tags_1)
		/sizeof(asn_DEF_CellInfoSI_ECN0_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CellInfoSI_ECN0_1,
	4,	/* Elements count */
	&asn_SPC_CellInfoSI_ECN0_specs_1	/* Additional specs */
};

