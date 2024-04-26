/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MeasurementReport-v4b0ext-IEs.h"

#include "InterFreqEventResults-LCR-r4-ext.h"
#include "MeasuredResultsList-LCR-r4-ext.h"
#include "PrimaryCPICH-Info.h"
asn_TYPE_member_t asn_MBR_MeasurementReport_v4b0ext_IEs_1[] = {
	{ ATF_POINTER, 3, offsetof(struct MeasurementReport_v4b0ext_IEs, interFreqEventResults_LCR),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterFreqEventResults_LCR_r4_ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqEventResults-LCR"
		},
	{ ATF_POINTER, 2, offsetof(struct MeasurementReport_v4b0ext_IEs, additionalMeasuredResults_LCR),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasuredResultsList_LCR_r4_ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"additionalMeasuredResults-LCR"
		},
	{ ATF_POINTER, 1, offsetof(struct MeasurementReport_v4b0ext_IEs, dummy),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
};
static const int asn_MAP_MeasurementReport_v4b0ext_IEs_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasurementReport_v4b0ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interFreqEventResults-LCR */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* additionalMeasuredResults-LCR */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* dummy */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasurementReport_v4b0ext_IEs_specs_1 = {
	sizeof(struct MeasurementReport_v4b0ext_IEs),
	offsetof(struct MeasurementReport_v4b0ext_IEs, _asn_ctx),
	asn_MAP_MeasurementReport_v4b0ext_IEs_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_MeasurementReport_v4b0ext_IEs_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementReport_v4b0ext_IEs = {
	"MeasurementReport-v4b0ext-IEs",
	"MeasurementReport-v4b0ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1,
	sizeof(asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1)
		/sizeof(asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1)
		/sizeof(asn_DEF_MeasurementReport_v4b0ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasurementReport_v4b0ext_IEs_1,
	3,	/* Elements count */
	&asn_SPC_MeasurementReport_v4b0ext_IEs_specs_1	/* Additional specs */
};

