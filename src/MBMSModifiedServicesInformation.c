/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMSModifiedServicesInformation.h"

#include "MBMS-ModifedServiceList-r6.h"
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_endOfModifiedMCCHInformation_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 16)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_mbms_ReacquireMCCH_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_mbms_ReacquireMCCH_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_mbms_AllUnmodifiedPTMServices_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_mbms_AllUnmodifiedPTMServices_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_endOfModifiedMCCHInformation_constr_6 CC_NOTUSED = {
	{ 1, 1 }	/* (1..16) */,
	-1};
static asn_per_constraints_t asn_PER_memb_endOfModifiedMCCHInformation_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  1,  16 }	/* (1..16) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_mbms_ReacquireMCCH_value2enum_3[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_mbms_ReacquireMCCH_enum2value_3[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_mbms_ReacquireMCCH_specs_3 = {
	asn_MAP_mbms_ReacquireMCCH_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_mbms_ReacquireMCCH_enum2value_3,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_mbms_ReacquireMCCH_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mbms_ReacquireMCCH_3 = {
	"mbms-ReacquireMCCH",
	"mbms-ReacquireMCCH",
	&asn_OP_NativeEnumerated,
	asn_DEF_mbms_ReacquireMCCH_tags_3,
	sizeof(asn_DEF_mbms_ReacquireMCCH_tags_3)
		/sizeof(asn_DEF_mbms_ReacquireMCCH_tags_3[0]) - 1, /* 1 */
	asn_DEF_mbms_ReacquireMCCH_tags_3,	/* Same as above */
	sizeof(asn_DEF_mbms_ReacquireMCCH_tags_3)
		/sizeof(asn_DEF_mbms_ReacquireMCCH_tags_3[0]), /* 2 */
	{ &asn_OER_type_mbms_ReacquireMCCH_constr_3, &asn_PER_type_mbms_ReacquireMCCH_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_mbms_ReacquireMCCH_specs_3	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_mbms_AllUnmodifiedPTMServices_value2enum_8[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_mbms_AllUnmodifiedPTMServices_enum2value_8[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_mbms_AllUnmodifiedPTMServices_specs_8 = {
	asn_MAP_mbms_AllUnmodifiedPTMServices_value2enum_8,	/* "tag" => N; sorted by tag */
	asn_MAP_mbms_AllUnmodifiedPTMServices_enum2value_8,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mbms_AllUnmodifiedPTMServices_8 = {
	"mbms-AllUnmodifiedPTMServices",
	"mbms-AllUnmodifiedPTMServices",
	&asn_OP_NativeEnumerated,
	asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8,
	sizeof(asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8)
		/sizeof(asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8[0]) - 1, /* 1 */
	asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8,	/* Same as above */
	sizeof(asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8)
		/sizeof(asn_DEF_mbms_AllUnmodifiedPTMServices_tags_8[0]), /* 2 */
	{ &asn_OER_type_mbms_AllUnmodifiedPTMServices_constr_8, &asn_PER_type_mbms_AllUnmodifiedPTMServices_constr_8, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_mbms_AllUnmodifiedPTMServices_specs_8	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_11 = {
	sizeof(struct MBMSModifiedServicesInformation__nonCriticalExtensions),
	offsetof(struct MBMSModifiedServicesInformation__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_11 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_11,
	sizeof(asn_DEF_nonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_11[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_11,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_11	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_MBMSModifiedServicesInformation_1[] = {
	{ ATF_POINTER, 4, offsetof(struct MBMSModifiedServicesInformation, modifedServiceList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ModifedServiceList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modifedServiceList"
		},
	{ ATF_POINTER, 3, offsetof(struct MBMSModifiedServicesInformation, mbms_ReacquireMCCH),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_mbms_ReacquireMCCH_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-ReacquireMCCH"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMSModifiedServicesInformation, mbms_DynamicPersistenceLevel),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DynamicPersistenceLevel,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-DynamicPersistenceLevel"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMSModifiedServicesInformation, endOfModifiedMCCHInformation),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_endOfModifiedMCCHInformation_constr_6, &asn_PER_memb_endOfModifiedMCCHInformation_constr_6,  memb_endOfModifiedMCCHInformation_constraint_1 },
		0, 0, /* No default value */
		"endOfModifiedMCCHInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMSModifiedServicesInformation, mbmsNumberOfNeighbourCells),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_NumberOfNeighbourCells_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbmsNumberOfNeighbourCells"
		},
	{ ATF_POINTER, 3, offsetof(struct MBMSModifiedServicesInformation, mbms_AllUnmodifiedPTMServices),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_mbms_AllUnmodifiedPTMServices_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-AllUnmodifiedPTMServices"
		},
	{ ATF_POINTER, 2, offsetof(struct MBMSModifiedServicesInformation, mbms_PTMActivationTime),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_PTMActivationTime_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-PTMActivationTime"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMSModifiedServicesInformation, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_MBMSModifiedServicesInformation_oms_1[] = { 0, 1, 2, 3, 5, 6, 7 };
static const ber_tlv_tag_t asn_DEF_MBMSModifiedServicesInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMSModifiedServicesInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* modifedServiceList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mbms-ReacquireMCCH */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* mbms-DynamicPersistenceLevel */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* endOfModifiedMCCHInformation */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* mbmsNumberOfNeighbourCells */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* mbms-AllUnmodifiedPTMServices */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* mbms-PTMActivationTime */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* nonCriticalExtensions */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMSModifiedServicesInformation_specs_1 = {
	sizeof(struct MBMSModifiedServicesInformation),
	offsetof(struct MBMSModifiedServicesInformation, _asn_ctx),
	asn_MAP_MBMSModifiedServicesInformation_tag2el_1,
	8,	/* Count of tags in the map */
	asn_MAP_MBMSModifiedServicesInformation_oms_1,	/* Optional members */
	7, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMSModifiedServicesInformation = {
	"MBMSModifiedServicesInformation",
	"MBMSModifiedServicesInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMSModifiedServicesInformation_tags_1,
	sizeof(asn_DEF_MBMSModifiedServicesInformation_tags_1)
		/sizeof(asn_DEF_MBMSModifiedServicesInformation_tags_1[0]), /* 1 */
	asn_DEF_MBMSModifiedServicesInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMSModifiedServicesInformation_tags_1)
		/sizeof(asn_DEF_MBMSModifiedServicesInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMSModifiedServicesInformation_1,
	8,	/* Elements count */
	&asn_SPC_MBMSModifiedServicesInformation_specs_1	/* Additional specs */
};
