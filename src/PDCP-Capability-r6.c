/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PDCP-Capability-r6.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_reverseCompressionDepth_constraint_10(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 65535)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_losslessDLRLC_PDUSizeChange_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_losslessDLRLC_PDUSizeChange_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_supportForRfc2507_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_supportForRfc2507_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_reverseCompressionDepth_constr_12 CC_NOTUSED = {
	{ 2, 1 }	/* (0..65535) */,
	-1};
static asn_per_constraints_t asn_PER_memb_reverseCompressionDepth_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 16,  16,  0,  65535 }	/* (0..65535) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_supportForRfc3095_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_supportForRfc3095_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_losslessDLRLC_PDUSizeChange_value2enum_3[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_losslessDLRLC_PDUSizeChange_enum2value_3[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_losslessDLRLC_PDUSizeChange_specs_3 = {
	asn_MAP_losslessDLRLC_PDUSizeChange_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_losslessDLRLC_PDUSizeChange_enum2value_3,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_losslessDLRLC_PDUSizeChange_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_losslessDLRLC_PDUSizeChange_3 = {
	"losslessDLRLC-PDUSizeChange",
	"losslessDLRLC-PDUSizeChange",
	&asn_OP_NativeEnumerated,
	asn_DEF_losslessDLRLC_PDUSizeChange_tags_3,
	sizeof(asn_DEF_losslessDLRLC_PDUSizeChange_tags_3)
		/sizeof(asn_DEF_losslessDLRLC_PDUSizeChange_tags_3[0]) - 1, /* 1 */
	asn_DEF_losslessDLRLC_PDUSizeChange_tags_3,	/* Same as above */
	sizeof(asn_DEF_losslessDLRLC_PDUSizeChange_tags_3)
		/sizeof(asn_DEF_losslessDLRLC_PDUSizeChange_tags_3[0]), /* 2 */
	{ &asn_OER_type_losslessDLRLC_PDUSizeChange_constr_3, &asn_PER_type_losslessDLRLC_PDUSizeChange_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_losslessDLRLC_PDUSizeChange_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_supportForRfc2507_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6__supportForRfc2507, choice.notSupported),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notSupported"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6__supportForRfc2507, choice.supported),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxHcContextSpace_r5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supported"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_supportForRfc2507_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notSupported */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* supported */
};
static asn_CHOICE_specifics_t asn_SPC_supportForRfc2507_specs_5 = {
	sizeof(struct PDCP_Capability_r6__supportForRfc2507),
	offsetof(struct PDCP_Capability_r6__supportForRfc2507, _asn_ctx),
	offsetof(struct PDCP_Capability_r6__supportForRfc2507, present),
	sizeof(((struct PDCP_Capability_r6__supportForRfc2507 *)0)->present),
	asn_MAP_supportForRfc2507_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supportForRfc2507_5 = {
	"supportForRfc2507",
	"supportForRfc2507",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_supportForRfc2507_constr_5, &asn_PER_type_supportForRfc2507_constr_5, CHOICE_constraint },
	asn_MBR_supportForRfc2507_5,
	2,	/* Elements count */
	&asn_SPC_supportForRfc2507_specs_5	/* Additional specs */
};

static int asn_DFL_11_cmp_4(const void *sptr) {
	const MaxROHC_ContextSessions_r4_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 4 */
	return (*st != 4);
}
static int asn_DFL_11_set_4(void **sptr) {
	MaxROHC_ContextSessions_r4_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 4 */
	*st = 4;
	return 0;
}
static int asn_DFL_12_cmp_0(const void *sptr) {
	const long *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_12_set_0(void **sptr) {
	long *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static asn_TYPE_member_t asn_MBR_supported_10[] = {
	{ ATF_POINTER, 2, offsetof(struct PDCP_Capability_r6__supportForRfc3095__supported, maxROHC_ContextSessions),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxROHC_ContextSessions_r4,
		0,
		{ 0, 0, 0 },
		&asn_DFL_11_cmp_4,	/* Compare DEFAULT 4 */
		&asn_DFL_11_set_4,	/* Set DEFAULT 4 */
		"maxROHC-ContextSessions"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct PDCP_Capability_r6__supportForRfc3095__supported, reverseCompressionDepth),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_reverseCompressionDepth_constr_12, &asn_PER_memb_reverseCompressionDepth_constr_12,  memb_reverseCompressionDepth_constraint_10 },
		&asn_DFL_12_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_12_set_0,	/* Set DEFAULT 0 */
		"reverseCompressionDepth"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6__supportForRfc3095__supported, supportForRfc3095ContextRelocation),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supportForRfc3095ContextRelocation"
		},
};
static const int asn_MAP_supported_oms_10[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_supported_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_supported_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxROHC-ContextSessions */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* reverseCompressionDepth */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* supportForRfc3095ContextRelocation */
};
static asn_SEQUENCE_specifics_t asn_SPC_supported_specs_10 = {
	sizeof(struct PDCP_Capability_r6__supportForRfc3095__supported),
	offsetof(struct PDCP_Capability_r6__supportForRfc3095__supported, _asn_ctx),
	asn_MAP_supported_tag2el_10,
	3,	/* Count of tags in the map */
	asn_MAP_supported_oms_10,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supported_10 = {
	"supported",
	"supported",
	&asn_OP_SEQUENCE,
	asn_DEF_supported_tags_10,
	sizeof(asn_DEF_supported_tags_10)
		/sizeof(asn_DEF_supported_tags_10[0]) - 1, /* 1 */
	asn_DEF_supported_tags_10,	/* Same as above */
	sizeof(asn_DEF_supported_tags_10)
		/sizeof(asn_DEF_supported_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_supported_10,
	3,	/* Elements count */
	&asn_SPC_supported_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_supportForRfc3095_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6__supportForRfc3095, choice.notSupported),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notSupported"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6__supportForRfc3095, choice.supported),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_supported_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supported"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_supportForRfc3095_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notSupported */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* supported */
};
static asn_CHOICE_specifics_t asn_SPC_supportForRfc3095_specs_8 = {
	sizeof(struct PDCP_Capability_r6__supportForRfc3095),
	offsetof(struct PDCP_Capability_r6__supportForRfc3095, _asn_ctx),
	offsetof(struct PDCP_Capability_r6__supportForRfc3095, present),
	sizeof(((struct PDCP_Capability_r6__supportForRfc3095 *)0)->present),
	asn_MAP_supportForRfc3095_tag2el_8,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supportForRfc3095_8 = {
	"supportForRfc3095",
	"supportForRfc3095",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_supportForRfc3095_constr_8, &asn_PER_type_supportForRfc3095_constr_8, CHOICE_constraint },
	asn_MBR_supportForRfc3095_8,
	2,	/* Elements count */
	&asn_SPC_supportForRfc3095_specs_8	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_PDCP_Capability_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6, losslessSRNS_RelocationSupport),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"losslessSRNS-RelocationSupport"
		},
	{ ATF_POINTER, 1, offsetof(struct PDCP_Capability_r6, losslessDLRLC_PDUSizeChange),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_losslessDLRLC_PDUSizeChange_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"losslessDLRLC-PDUSizeChange"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6, supportForRfc2507),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_supportForRfc2507_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supportForRfc2507"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Capability_r6, supportForRfc3095),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_supportForRfc3095_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supportForRfc3095"
		},
};
static const int asn_MAP_PDCP_Capability_r6_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_PDCP_Capability_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PDCP_Capability_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* losslessSRNS-RelocationSupport */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* losslessDLRLC-PDUSizeChange */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* supportForRfc2507 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* supportForRfc3095 */
};
asn_SEQUENCE_specifics_t asn_SPC_PDCP_Capability_r6_specs_1 = {
	sizeof(struct PDCP_Capability_r6),
	offsetof(struct PDCP_Capability_r6, _asn_ctx),
	asn_MAP_PDCP_Capability_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_PDCP_Capability_r6_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PDCP_Capability_r6 = {
	"PDCP-Capability-r6",
	"PDCP-Capability-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_PDCP_Capability_r6_tags_1,
	sizeof(asn_DEF_PDCP_Capability_r6_tags_1)
		/sizeof(asn_DEF_PDCP_Capability_r6_tags_1[0]), /* 1 */
	asn_DEF_PDCP_Capability_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_PDCP_Capability_r6_tags_1)
		/sizeof(asn_DEF_PDCP_Capability_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PDCP_Capability_r6_1,
	4,	/* Elements count */
	&asn_SPC_PDCP_Capability_r6_specs_1	/* Additional specs */
};

