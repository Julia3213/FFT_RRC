/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MeasurementReportingMode.h"

asn_TYPE_member_t asn_MBR_MeasurementReportingMode_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementReportingMode, measurementReportTransferMode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransferMode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measurementReportTransferMode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementReportingMode, periodicalOrEventTrigger),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PeriodicalOrEventTrigger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"periodicalOrEventTrigger"
		},
};
static const ber_tlv_tag_t asn_DEF_MeasurementReportingMode_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasurementReportingMode_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* measurementReportTransferMode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* periodicalOrEventTrigger */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasurementReportingMode_specs_1 = {
	sizeof(struct MeasurementReportingMode),
	offsetof(struct MeasurementReportingMode, _asn_ctx),
	asn_MAP_MeasurementReportingMode_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementReportingMode = {
	"MeasurementReportingMode",
	"MeasurementReportingMode",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasurementReportingMode_tags_1,
	sizeof(asn_DEF_MeasurementReportingMode_tags_1)
		/sizeof(asn_DEF_MeasurementReportingMode_tags_1[0]), /* 1 */
	asn_DEF_MeasurementReportingMode_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasurementReportingMode_tags_1)
		/sizeof(asn_DEF_MeasurementReportingMode_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasurementReportingMode_1,
	2,	/* Elements count */
	&asn_SPC_MeasurementReportingMode_specs_1	/* Additional specs */
};

