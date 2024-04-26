/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-HSPDSCH-TS-Configuration-VHCR.h"

static asn_oer_constraints_t asn_OER_type_DL_HSPDSCH_TS_Configuration_VHCR_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..13)) */};
asn_per_constraints_t asn_PER_type_DL_HSPDSCH_TS_Configuration_VHCR_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 4,  4,  1,  13 }	/* (SIZE(1..13)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_Member_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_HSPDSCH_TS_Configuration_VHCR__Member, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_HSPDSCH_TS_Configuration_VHCR__Member, midambleShiftAndBurstType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftAndBurstType_DL_VHCR,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"midambleShiftAndBurstType"
		},
};
static const ber_tlv_tag_t asn_DEF_Member_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Member_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* midambleShiftAndBurstType */
};
static asn_SEQUENCE_specifics_t asn_SPC_Member_specs_2 = {
	sizeof(struct DL_HSPDSCH_TS_Configuration_VHCR__Member),
	offsetof(struct DL_HSPDSCH_TS_Configuration_VHCR__Member, _asn_ctx),
	asn_MAP_Member_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_Member_2 = {
	"SEQUENCE",
	"SEQUENCE",
	&asn_OP_SEQUENCE,
	asn_DEF_Member_tags_2,
	sizeof(asn_DEF_Member_tags_2)
		/sizeof(asn_DEF_Member_tags_2[0]), /* 1 */
	asn_DEF_Member_tags_2,	/* Same as above */
	sizeof(asn_DEF_Member_tags_2)
		/sizeof(asn_DEF_Member_tags_2[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Member_2,
	2,	/* Elements count */
	&asn_SPC_Member_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DL_HSPDSCH_TS_Configuration_VHCR_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Member_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_DL_HSPDSCH_TS_Configuration_VHCR_specs_1 = {
	sizeof(struct DL_HSPDSCH_TS_Configuration_VHCR),
	offsetof(struct DL_HSPDSCH_TS_Configuration_VHCR, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR = {
	"DL-HSPDSCH-TS-Configuration-VHCR",
	"DL-HSPDSCH-TS-Configuration-VHCR",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1,
	sizeof(asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1)
		/sizeof(asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1[0]), /* 1 */
	asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1)
		/sizeof(asn_DEF_DL_HSPDSCH_TS_Configuration_VHCR_tags_1[0]), /* 1 */
	{ &asn_OER_type_DL_HSPDSCH_TS_Configuration_VHCR_constr_1, &asn_PER_type_DL_HSPDSCH_TS_Configuration_VHCR_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_DL_HSPDSCH_TS_Configuration_VHCR_1,
	1,	/* Single element */
	&asn_SPC_DL_HSPDSCH_TS_Configuration_VHCR_specs_1	/* Additional specs */
};

