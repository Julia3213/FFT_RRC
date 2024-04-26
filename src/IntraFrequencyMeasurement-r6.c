/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "IntraFrequencyMeasurement-r6.h"

#include "IntraFreqCellInfoList-r4.h"
#include "IntraFreqMeasQuantity.h"
#include "IntraFreqReportingQuantity.h"
#include "MeasurementValidity.h"
asn_TYPE_member_t asn_MBR_IntraFrequencyMeasurement_r6_1[] = {
	{ ATF_POINTER, 4, offsetof(struct IntraFrequencyMeasurement_r6, intraFreqCellInfoList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntraFreqCellInfoList_r4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"intraFreqCellInfoList"
		},
	{ ATF_POINTER, 3, offsetof(struct IntraFrequencyMeasurement_r6, intraFreqMeasQuantity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntraFreqMeasQuantity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"intraFreqMeasQuantity"
		},
	{ ATF_POINTER, 2, offsetof(struct IntraFrequencyMeasurement_r6, intraFreqReportingQuantity),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntraFreqReportingQuantity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"intraFreqReportingQuantity"
		},
	{ ATF_POINTER, 1, offsetof(struct IntraFrequencyMeasurement_r6, measurementValidity),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasurementValidity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measurementValidity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFrequencyMeasurement_r6, reportCriteria),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_IntraFreqReportCriteria_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"reportCriteria"
		},
};
static const int asn_MAP_IntraFrequencyMeasurement_r6_oms_1[] = { 0, 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_IntraFrequencyMeasurement_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_IntraFrequencyMeasurement_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* intraFreqCellInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* intraFreqMeasQuantity */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* intraFreqReportingQuantity */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* measurementValidity */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* reportCriteria */
};
asn_SEQUENCE_specifics_t asn_SPC_IntraFrequencyMeasurement_r6_specs_1 = {
	sizeof(struct IntraFrequencyMeasurement_r6),
	offsetof(struct IntraFrequencyMeasurement_r6, _asn_ctx),
	asn_MAP_IntraFrequencyMeasurement_r6_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_IntraFrequencyMeasurement_r6_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_IntraFrequencyMeasurement_r6 = {
	"IntraFrequencyMeasurement-r6",
	"IntraFrequencyMeasurement-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_IntraFrequencyMeasurement_r6_tags_1,
	sizeof(asn_DEF_IntraFrequencyMeasurement_r6_tags_1)
		/sizeof(asn_DEF_IntraFrequencyMeasurement_r6_tags_1[0]), /* 1 */
	asn_DEF_IntraFrequencyMeasurement_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_IntraFrequencyMeasurement_r6_tags_1)
		/sizeof(asn_DEF_IntraFrequencyMeasurement_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_IntraFrequencyMeasurement_r6_1,
	5,	/* Elements count */
	&asn_SPC_IntraFrequencyMeasurement_r6_specs_1	/* Additional specs */
};
