/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-MICHConfigurationInfo-r7.h"

#include "RepPerLengthOffset-MICH.h"
static int
memb_channelisationCodeList_constraint_20(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 2)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_channelisationCodeList_constr_23 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..2)) */};
static asn_per_constraints_t asn_PER_type_channelisationCodeList_constr_23 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 1,  1,  1,  2 }	/* (SIZE(1..2)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_channelisationCodeList_constr_23 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..2)) */};
static asn_per_constraints_t asn_PER_memb_channelisationCodeList_constr_23 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 1,  1,  1,  2 }	/* (SIZE(1..2)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_mode_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_mode_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_fdd_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__fdd, channelisationCode256),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ChannelisationCode256,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelisationCode256"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__fdd, ni_CountPerFrame),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_NI_CountPerFrame,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ni-CountPerFrame"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__fdd, sttd_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sttd-Indicator"
		},
};
static const ber_tlv_tag_t asn_DEF_fdd_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* channelisationCode256 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ni-CountPerFrame */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* sttd-Indicator */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_4 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode__fdd),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_4,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_4 = {
	"fdd",
	"fdd",
	&asn_OP_SEQUENCE,
	asn_DEF_fdd_tags_4,
	sizeof(asn_DEF_fdd_tags_4)
		/sizeof(asn_DEF_fdd_tags_4[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_4,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_4)
		/sizeof(asn_DEF_fdd_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fdd_4,
	3,	/* Elements count */
	&asn_SPC_fdd_specs_4	/* Additional specs */
};

static int asn_DFL_13_cmp_0(const void *sptr) {
	const MBMS_MICHNotificationIndLength_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_13_set_0(void **sptr) {
	MBMS_MICHNotificationIndLength_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static asn_TYPE_member_t asn_MBR_tdd384_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, midambleShiftAndBurstType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftAndBurstType,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleShiftAndBurstType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, channelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelisationCode"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, repetitionPeriodLengthOffset),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RepPerLengthOffset_MICH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"repetitionPeriodLengthOffset"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, mbmsNotificationIndLength),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_MICHNotificationIndLength,
		0,
		{ 0, 0, 0 },
		&asn_DFL_13_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_13_set_0,	/* Set DEFAULT 0 */
		"mbmsNotificationIndLength"
		},
};
static const int asn_MAP_tdd384_oms_8[] = { 3, 4 };
static const ber_tlv_tag_t asn_DEF_tdd384_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd384_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* midambleShiftAndBurstType */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* channelisationCode */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* repetitionPeriodLengthOffset */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* mbmsNotificationIndLength */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd384_specs_8 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd384, _asn_ctx),
	asn_MAP_tdd384_tag2el_8,
	5,	/* Count of tags in the map */
	asn_MAP_tdd384_oms_8,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd384_8 = {
	"tdd384",
	"tdd384",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd384_tags_8,
	sizeof(asn_DEF_tdd384_tags_8)
		/sizeof(asn_DEF_tdd384_tags_8[0]) - 1, /* 1 */
	asn_DEF_tdd384_tags_8,	/* Same as above */
	sizeof(asn_DEF_tdd384_tags_8)
		/sizeof(asn_DEF_tdd384_tags_8[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd384_8,
	5,	/* Elements count */
	&asn_SPC_tdd384_specs_8	/* Additional specs */
};

static int asn_DFL_19_cmp_0(const void *sptr) {
	const MBMS_MICHNotificationIndLength_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_19_set_0(void **sptr) {
	MBMS_MICHNotificationIndLength_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static asn_TYPE_member_t asn_MBR_tdd768_14[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, midambleShiftAndBurstType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftAndBurstType_VHCR,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleShiftAndBurstType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, channelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelisationCode"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, repetitionPeriodLengthOffset),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RepPerLengthOffset_MICH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"repetitionPeriodLengthOffset"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, mbmsNotificationIndLength),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_MICHNotificationIndLength,
		0,
		{ 0, 0, 0 },
		&asn_DFL_19_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_19_set_0,	/* Set DEFAULT 0 */
		"mbmsNotificationIndLength"
		},
};
static const int asn_MAP_tdd768_oms_14[] = { 3, 4 };
static const ber_tlv_tag_t asn_DEF_tdd768_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd768_tag2el_14[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* midambleShiftAndBurstType */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* channelisationCode */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* repetitionPeriodLengthOffset */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* mbmsNotificationIndLength */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd768_specs_14 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd768, _asn_ctx),
	asn_MAP_tdd768_tag2el_14,
	5,	/* Count of tags in the map */
	asn_MAP_tdd768_oms_14,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd768_14 = {
	"tdd768",
	"tdd768",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd768_tags_14,
	sizeof(asn_DEF_tdd768_tags_14)
		/sizeof(asn_DEF_tdd768_tags_14[0]) - 1, /* 1 */
	asn_DEF_tdd768_tags_14,	/* Same as above */
	sizeof(asn_DEF_tdd768_tags_14)
		/sizeof(asn_DEF_tdd768_tags_14[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd768_14,
	5,	/* Elements count */
	&asn_SPC_tdd768_specs_14	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_channelisationCodeList_23[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (10 << 2)),
		0,
		&asn_DEF_DL_TS_ChannelisationCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_channelisationCodeList_tags_23[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_channelisationCodeList_specs_23 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128__channelisationCodeList),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128__channelisationCodeList, _asn_ctx),
	1,	/* XER encoding is XMLValueList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_channelisationCodeList_23 = {
	"channelisationCodeList",
	"channelisationCodeList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_channelisationCodeList_tags_23,
	sizeof(asn_DEF_channelisationCodeList_tags_23)
		/sizeof(asn_DEF_channelisationCodeList_tags_23[0]) - 1, /* 1 */
	asn_DEF_channelisationCodeList_tags_23,	/* Same as above */
	sizeof(asn_DEF_channelisationCodeList_tags_23)
		/sizeof(asn_DEF_channelisationCodeList_tags_23[0]), /* 2 */
	{ &asn_OER_type_channelisationCodeList_constr_23, &asn_PER_type_channelisationCodeList_constr_23, SEQUENCE_OF_constraint },
	asn_MBR_channelisationCodeList_23,
	1,	/* Single element */
	&asn_SPC_channelisationCodeList_specs_23	/* Additional specs */
};

static int asn_DFL_26_cmp_0(const void *sptr) {
	const MBMS_MICHNotificationIndLength_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_26_set_0(void **sptr) {
	MBMS_MICHNotificationIndLength_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static asn_TYPE_member_t asn_MBR_tdd128_20[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber_LCR_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, midambleShiftAndBurstType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftAndBurstType_LCR_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleShiftAndBurstType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, channelisationCodeList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_channelisationCodeList_23,
		0,
		{ &asn_OER_memb_channelisationCodeList_constr_23, &asn_PER_memb_channelisationCodeList_constr_23,  memb_channelisationCodeList_constraint_20 },
		0, 0, /* No default value */
		"channelisationCodeList"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, repetitionPeriodLengthOffset),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RepPerLengthOffset_MICH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"repetitionPeriodLengthOffset"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, mbmsNotificationIndLength),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_MICHNotificationIndLength,
		0,
		{ 0, 0, 0 },
		&asn_DFL_26_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_26_set_0,	/* Set DEFAULT 0 */
		"mbmsNotificationIndLength"
		},
};
static const int asn_MAP_tdd128_oms_20[] = { 3, 4 };
static const ber_tlv_tag_t asn_DEF_tdd128_tags_20[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tdd128_tag2el_20[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* midambleShiftAndBurstType */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* channelisationCodeList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* repetitionPeriodLengthOffset */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* mbmsNotificationIndLength */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd128_specs_20 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode__tdd128, _asn_ctx),
	asn_MAP_tdd128_tag2el_20,
	5,	/* Count of tags in the map */
	asn_MAP_tdd128_oms_20,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd128_20 = {
	"tdd128",
	"tdd128",
	&asn_OP_SEQUENCE,
	asn_DEF_tdd128_tags_20,
	sizeof(asn_DEF_tdd128_tags_20)
		/sizeof(asn_DEF_tdd128_tags_20[0]) - 1, /* 1 */
	asn_DEF_tdd128_tags_20,	/* Same as above */
	sizeof(asn_DEF_tdd128_tags_20)
		/sizeof(asn_DEF_tdd128_tags_20[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tdd128_20,
	5,	/* Elements count */
	&asn_SPC_tdd128_specs_20	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_mode_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, choice.tdd384),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd384_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd384"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, choice.tdd768),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_tdd768_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd768"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, choice.tdd128),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_tdd128_20,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tdd128"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_mode_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tdd384 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* tdd768 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* tdd128 */
};
static asn_CHOICE_specifics_t asn_SPC_mode_specs_3 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7__mode),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, _asn_ctx),
	offsetof(struct MBMS_MICHConfigurationInfo_r7__mode, present),
	sizeof(((struct MBMS_MICHConfigurationInfo_r7__mode *)0)->present),
	asn_MAP_mode_tag2el_3,
	4,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mode_3 = {
	"mode",
	"mode",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_mode_constr_3, &asn_PER_type_mode_constr_3, CHOICE_constraint },
	asn_MBR_mode_3,
	4,	/* Elements count */
	&asn_SPC_mode_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_MBMS_MICHConfigurationInfo_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7, michPowerOffset),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_MICHPowerOffset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"michPowerOffset"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_MICHConfigurationInfo_r7, mode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_mode_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mode"
		},
};
static const ber_tlv_tag_t asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMS_MICHConfigurationInfo_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* michPowerOffset */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mode */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMS_MICHConfigurationInfo_r7_specs_1 = {
	sizeof(struct MBMS_MICHConfigurationInfo_r7),
	offsetof(struct MBMS_MICHConfigurationInfo_r7, _asn_ctx),
	asn_MAP_MBMS_MICHConfigurationInfo_r7_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_MICHConfigurationInfo_r7 = {
	"MBMS-MICHConfigurationInfo-r7",
	"MBMS-MICHConfigurationInfo-r7",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1,
	sizeof(asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1)
		/sizeof(asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1[0]), /* 1 */
	asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1)
		/sizeof(asn_DEF_MBMS_MICHConfigurationInfo_r7_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMS_MICHConfigurationInfo_r7_1,
	2,	/* Elements count */
	&asn_SPC_MBMS_MICHConfigurationInfo_r7_specs_1	/* Additional specs */
};

