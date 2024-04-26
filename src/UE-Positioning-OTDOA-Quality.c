/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-Positioning-OTDOA-Quality.h"

static int
memb_stdResolution_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 2)) {
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
memb_numberOfOTDOA_Measurements_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 3)) {
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
memb_stdOfOTDOA_Measurements_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 5)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_stdResolution_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	2	/* (SIZE(2..2)) */};
static asn_per_constraints_t asn_PER_memb_stdResolution_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  2,  2 }	/* (SIZE(2..2)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_numberOfOTDOA_Measurements_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	3	/* (SIZE(3..3)) */};
static asn_per_constraints_t asn_PER_memb_numberOfOTDOA_Measurements_constr_3 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  3,  3 }	/* (SIZE(3..3)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_stdOfOTDOA_Measurements_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	5	/* (SIZE(5..5)) */};
static asn_per_constraints_t asn_PER_memb_stdOfOTDOA_Measurements_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  5,  5 }	/* (SIZE(5..5)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_UE_Positioning_OTDOA_Quality_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_Quality, stdResolution),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_stdResolution_constr_2, &asn_PER_memb_stdResolution_constr_2,  memb_stdResolution_constraint_1 },
		0, 0, /* No default value */
		"stdResolution"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_Quality, numberOfOTDOA_Measurements),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_numberOfOTDOA_Measurements_constr_3, &asn_PER_memb_numberOfOTDOA_Measurements_constr_3,  memb_numberOfOTDOA_Measurements_constraint_1 },
		0, 0, /* No default value */
		"numberOfOTDOA-Measurements"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_OTDOA_Quality, stdOfOTDOA_Measurements),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_stdOfOTDOA_Measurements_constr_4, &asn_PER_memb_stdOfOTDOA_Measurements_constr_4,  memb_stdOfOTDOA_Measurements_constraint_1 },
		0, 0, /* No default value */
		"stdOfOTDOA-Measurements"
		},
};
static const ber_tlv_tag_t asn_DEF_UE_Positioning_OTDOA_Quality_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_Positioning_OTDOA_Quality_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* stdResolution */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* numberOfOTDOA-Measurements */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* stdOfOTDOA-Measurements */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_OTDOA_Quality_specs_1 = {
	sizeof(struct UE_Positioning_OTDOA_Quality),
	offsetof(struct UE_Positioning_OTDOA_Quality, _asn_ctx),
	asn_MAP_UE_Positioning_OTDOA_Quality_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_Quality = {
	"UE-Positioning-OTDOA-Quality",
	"UE-Positioning-OTDOA-Quality",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_Positioning_OTDOA_Quality_tags_1,
	sizeof(asn_DEF_UE_Positioning_OTDOA_Quality_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_Quality_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_OTDOA_Quality_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_OTDOA_Quality_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_Quality_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_Positioning_OTDOA_Quality_1,
	3,	/* Elements count */
	&asn_SPC_UE_Positioning_OTDOA_Quality_specs_1	/* Additional specs */
};
