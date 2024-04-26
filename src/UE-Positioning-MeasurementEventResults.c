/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-Positioning-MeasurementEventResults.h"

static asn_oer_constraints_t asn_OER_type_UE_Positioning_MeasurementEventResults_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_UE_Positioning_MeasurementEventResults_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_UE_Positioning_MeasurementEventResults_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_MeasurementEventResults, choice.event7a),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_PositionEstimateInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"event7a"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_MeasurementEventResults, choice.event7b),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_OTDOA_Measurement,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"event7b"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_MeasurementEventResults, choice.event7c),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GPS_MeasurementResults,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"event7c"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_MeasurementEventResults, choice.spare),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spare"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_UE_Positioning_MeasurementEventResults_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* event7a */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* event7b */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* event7c */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* spare */
};
asn_CHOICE_specifics_t asn_SPC_UE_Positioning_MeasurementEventResults_specs_1 = {
	sizeof(struct UE_Positioning_MeasurementEventResults),
	offsetof(struct UE_Positioning_MeasurementEventResults, _asn_ctx),
	offsetof(struct UE_Positioning_MeasurementEventResults, present),
	sizeof(((struct UE_Positioning_MeasurementEventResults *)0)->present),
	asn_MAP_UE_Positioning_MeasurementEventResults_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_MeasurementEventResults = {
	"UE-Positioning-MeasurementEventResults",
	"UE-Positioning-MeasurementEventResults",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_UE_Positioning_MeasurementEventResults_constr_1, &asn_PER_type_UE_Positioning_MeasurementEventResults_constr_1, CHOICE_constraint },
	asn_MBR_UE_Positioning_MeasurementEventResults_1,
	4,	/* Elements count */
	&asn_SPC_UE_Positioning_MeasurementEventResults_specs_1	/* Additional specs */
};

