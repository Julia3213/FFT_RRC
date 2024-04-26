/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MeasurementReport-v590ext-IEs.h"

#include "MeasuredResults-v590ext.h"
asn_TYPE_member_t asn_MBR_MeasurementReport_v590ext_IEs_1[] = {
	{ ATF_POINTER, 1, offsetof(struct MeasurementReport_v590ext_IEs, measuredResults_v590ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_MeasuredResults_v590ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measuredResults-v590ext"
		},
};
static const int asn_MAP_MeasurementReport_v590ext_IEs_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_MeasurementReport_v590ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasurementReport_v590ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* measuredResults-v590ext */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasurementReport_v590ext_IEs_specs_1 = {
	sizeof(struct MeasurementReport_v590ext_IEs),
	offsetof(struct MeasurementReport_v590ext_IEs, _asn_ctx),
	asn_MAP_MeasurementReport_v590ext_IEs_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_MeasurementReport_v590ext_IEs_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementReport_v590ext_IEs = {
	"MeasurementReport-v590ext-IEs",
	"MeasurementReport-v590ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasurementReport_v590ext_IEs_tags_1,
	sizeof(asn_DEF_MeasurementReport_v590ext_IEs_tags_1)
		/sizeof(asn_DEF_MeasurementReport_v590ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_MeasurementReport_v590ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasurementReport_v590ext_IEs_tags_1)
		/sizeof(asn_DEF_MeasurementReport_v590ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasurementReport_v590ext_IEs_1,
	1,	/* Elements count */
	&asn_SPC_MeasurementReport_v590ext_IEs_specs_1	/* Additional specs */
};
