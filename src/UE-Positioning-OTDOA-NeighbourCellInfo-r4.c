/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-Positioning-OTDOA-NeighbourCellInfo-r4.h"

#include "FrequencyInfo.h"
#include "UE-Positioning-IPDL-Parameters-r4.h"
static int
memb_relativeNorth_constraint_14(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -20000 && value <= 20000)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_relativeEast_constraint_14(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -20000 && value <= 20000)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_relativeAltitude_constraint_14(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -4000 && value <= 4000)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_roundTripTime_constraint_14(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 32766)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_relativeNorth_constr_15 CC_NOTUSED = {
	{ 2, 0 }	/* (-20000..20000) */,
	-1};
static asn_per_constraints_t asn_PER_memb_relativeNorth_constr_15 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 16,  16, -20000,  20000 }	/* (-20000..20000) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_relativeEast_constr_16 CC_NOTUSED = {
	{ 2, 0 }	/* (-20000..20000) */,
	-1};
static asn_per_constraints_t asn_PER_memb_relativeEast_constr_16 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 16,  16, -20000,  20000 }	/* (-20000..20000) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_relativeAltitude_constr_17 CC_NOTUSED = {
	{ 2, 0 }	/* (-4000..4000) */,
	-1};
static asn_per_constraints_t asn_PER_memb_relativeAltitude_constr_17 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 13,  13, -4000,  4000 }	/* (-4000..4000) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_roundTripTime_constr_19 CC_NOTUSED = {
	{ 2, 1 }	/* (0..32766) */,
	-1};
static asn_per_constraints_t asn_PER_memb_roundTripTime_constr_19 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 15,  15,  0,  32766 }	/* (0..32766) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_positioningMode_constr_13 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_positioningMode_constr_13 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__fdd, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-Info"
		},
};
static const ber_tlv_tag_t asn_DEF_fdd_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* primaryCPICH-Info */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_3 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__fdd),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_3,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_3 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_3,
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_3,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_3)
		/sizeof(asn_DEF_fdd_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_3,
	1,	/* Elements count */
	&asn_SPC_fdd_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__tdd, cellAndChannelIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellAndChannelIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellAndChannelIdentity"
		},
};
static const ber_tlv_tag_t asn_DEF_tdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* cellAndChannelIdentity */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_5 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__tdd),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_5,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_5 = {
	"tdd",
	"tdd",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd_tags_5,
	sizeof(asn_DEF_tdd_tags_5)
		/sizeof(asn_DEF_tdd_tags_5[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_5,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_5)
		/sizeof(asn_DEF_tdd_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd_5,
	1,	/* Elements count */
	&asn_SPC_tdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_2 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo, _asn_ctx),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo, present),
	sizeof(((struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_2 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_modeSpecificInfo_constr_2, &asn_PER_type_modeSpecificInfo_constr_2, CHOICE_constraint },
	asn_MBR_modeSpecificInfo_2,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_ueBased_14[] = {
	{ ATF_POINTER, 5, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, relativeNorth),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_relativeNorth_constr_15, &asn_PER_memb_relativeNorth_constr_15,  memb_relativeNorth_constraint_14 },
		0, 0, /* No default value */
		"relativeNorth"
		},
	{ ATF_POINTER, 4, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, relativeEast),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_relativeEast_constr_16, &asn_PER_memb_relativeEast_constr_16,  memb_relativeEast_constraint_14 },
		0, 0, /* No default value */
		"relativeEast"
		},
	{ ATF_POINTER, 3, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, relativeAltitude),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_relativeAltitude_constr_17, &asn_PER_memb_relativeAltitude_constr_17,  memb_relativeAltitude_constraint_14 },
		0, 0, /* No default value */
		"relativeAltitude"
		},
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, fineSFN_SFN),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FineSFN_SFN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fineSFN-SFN"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, roundTripTime),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_roundTripTime_constr_19, &asn_PER_memb_roundTripTime_constr_19,  memb_roundTripTime_constraint_14 },
		0, 0, /* No default value */
		"roundTripTime"
		},
};
static const int asn_MAP_ueBased_oms_14[] = { 0, 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_ueBased_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ueBased_tag2el_14[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* relativeNorth */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* relativeEast */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* relativeAltitude */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* fineSFN-SFN */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* roundTripTime */
};
static asn_SEQUENCE_specifics_t asn_SPC_ueBased_specs_14 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueBased, _asn_ctx),
	asn_MAP_ueBased_tag2el_14,
	5,	/* Count of tags in the map */
	asn_MAP_ueBased_oms_14,	/* Optional members */
	5, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueBased_14 = {
	"ueBased",
	"ueBased",
	&asn_OP_SEQUENCE,
	asn_DEF_ueBased_tags_14,
	sizeof(asn_DEF_ueBased_tags_14)
		/sizeof(asn_DEF_ueBased_tags_14[0]) - 1, /* 1 */
	asn_DEF_ueBased_tags_14,	/* Same as above */
	sizeof(asn_DEF_ueBased_tags_14)
		/sizeof(asn_DEF_ueBased_tags_14[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_ueBased_14,
	5,	/* Elements count */
	&asn_SPC_ueBased_specs_14	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_ueAssisted_tags_20[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_ueAssisted_specs_20 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueAssisted),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode__ueAssisted, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_ueAssisted_20 = {
	"ueAssisted",
	"ueAssisted",
	&asn_OP_SEQUENCE,
	asn_DEF_ueAssisted_tags_20,
	sizeof(asn_DEF_ueAssisted_tags_20)
		/sizeof(asn_DEF_ueAssisted_tags_20[0]) - 1, /* 1 */
	asn_DEF_ueAssisted_tags_20,	/* Same as above */
	sizeof(asn_DEF_ueAssisted_tags_20)
		/sizeof(asn_DEF_ueAssisted_tags_20[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_ueAssisted_specs_20	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_positioningMode_13[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode, choice.ueBased),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_ueBased_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ueBased"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode, choice.ueAssisted),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_ueAssisted_20,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ueAssisted"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_positioningMode_tag2el_13[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueBased */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ueAssisted */
};
static asn_CHOICE_specifics_t asn_SPC_positioningMode_specs_13 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode, _asn_ctx),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode, present),
	sizeof(((struct UE_Positioning_OTDOA_NeighbourCellInfo_r4__positioningMode *)0)->present),
	asn_MAP_positioningMode_tag2el_13,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_positioningMode_13 = {
	"positioningMode",
	"positioningMode",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_positioningMode_constr_13, &asn_PER_type_positioningMode_constr_13, CHOICE_constraint },
	asn_MBR_positioningMode_13,
	2,	/* Elements count */
	&asn_SPC_positioningMode_specs_13	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_UE_Positioning_OTDOA_NeighbourCellInfo_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modeSpecificInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, frequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"frequencyInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, ue_positioning_IPDL_Paremeters),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_IPDL_Parameters_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-positioning-IPDL-Paremeters"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, sfn_SFN_RelTimeDifference),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_SFN_RelTimeDifference1,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sfn-SFN-RelTimeDifference"
		},
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, sfn_Offset_Validity),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_Offset_Validity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sfn-Offset-Validity"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, sfn_SFN_Drift),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_SFN_Drift,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sfn-SFN-Drift"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, searchWindowSize),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OTDOA_SearchWindowSize,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"searchWindowSize"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, positioningMode),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_positioningMode_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"positioningMode"
		},
};
static const int asn_MAP_UE_Positioning_OTDOA_NeighbourCellInfo_r4_oms_1[] = { 1, 2, 4, 5 };
static const ber_tlv_tag_t asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* modeSpecificInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* frequencyInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ue-positioning-IPDL-Paremeters */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* sfn-SFN-RelTimeDifference */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* sfn-Offset-Validity */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* sfn-SFN-Drift */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* searchWindowSize */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* positioningMode */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_OTDOA_NeighbourCellInfo_r4_specs_1 = {
	sizeof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4),
	offsetof(struct UE_Positioning_OTDOA_NeighbourCellInfo_r4, _asn_ctx),
	asn_MAP_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tag2el_1,
	8,	/* Count of tags in the map */
	asn_MAP_UE_Positioning_OTDOA_NeighbourCellInfo_r4_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4 = {
	"UE-Positioning-OTDOA-NeighbourCellInfo-r4",
	"UE-Positioning-OTDOA-NeighbourCellInfo-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1,
	sizeof(asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_Positioning_OTDOA_NeighbourCellInfo_r4_1,
	8,	/* Elements count */
	&asn_SPC_UE_Positioning_OTDOA_NeighbourCellInfo_r4_specs_1	/* Additional specs */
};
