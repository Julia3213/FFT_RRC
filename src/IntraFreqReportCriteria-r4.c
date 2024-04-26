/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "IntraFreqReportCriteria-r4.h"

static asn_oer_constraints_t asn_OER_type_IntraFreqReportCriteria_r4_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_IntraFreqReportCriteria_r4_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_IntraFreqReportCriteria_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportCriteria_r4, choice.intraFreqReportingCriteria),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntraFreqReportingCriteria_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"intraFreqReportingCriteria"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportCriteria_r4, choice.periodicalReportingCriteria),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PeriodicalWithReportingCellStatus,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"periodicalReportingCriteria"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportCriteria_r4, choice.noReporting),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ReportingCellStatusOpt,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"noReporting"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_IntraFreqReportCriteria_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* intraFreqReportingCriteria */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* periodicalReportingCriteria */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* noReporting */
};
asn_CHOICE_specifics_t asn_SPC_IntraFreqReportCriteria_r4_specs_1 = {
	sizeof(struct IntraFreqReportCriteria_r4),
	offsetof(struct IntraFreqReportCriteria_r4, _asn_ctx),
	offsetof(struct IntraFreqReportCriteria_r4, present),
	sizeof(((struct IntraFreqReportCriteria_r4 *)0)->present),
	asn_MAP_IntraFreqReportCriteria_r4_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_IntraFreqReportCriteria_r4 = {
	"IntraFreqReportCriteria-r4",
	"IntraFreqReportCriteria-r4",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_IntraFreqReportCriteria_r4_constr_1, &asn_PER_type_IntraFreqReportCriteria_r4_constr_1, CHOICE_constraint },
	asn_MBR_IntraFreqReportCriteria_r4_1,
	3,	/* Elements count */
	&asn_SPC_IntraFreqReportCriteria_r4_specs_1	/* Additional specs */
};

