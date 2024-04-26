/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MeasurementControl-v3a0ext.h"

asn_TYPE_member_t asn_MBR_MeasurementControl_v3a0ext_1[] = {
	{ ATF_POINTER, 1, offsetof(struct MeasurementControl_v3a0ext, sfn_Offset_Validity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_Offset_Validity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sfn-Offset-Validity"
		},
};
static const int asn_MAP_MeasurementControl_v3a0ext_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_MeasurementControl_v3a0ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasurementControl_v3a0ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* sfn-Offset-Validity */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasurementControl_v3a0ext_specs_1 = {
	sizeof(struct MeasurementControl_v3a0ext),
	offsetof(struct MeasurementControl_v3a0ext, _asn_ctx),
	asn_MAP_MeasurementControl_v3a0ext_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_MeasurementControl_v3a0ext_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementControl_v3a0ext = {
	"MeasurementControl-v3a0ext",
	"MeasurementControl-v3a0ext",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasurementControl_v3a0ext_tags_1,
	sizeof(asn_DEF_MeasurementControl_v3a0ext_tags_1)
		/sizeof(asn_DEF_MeasurementControl_v3a0ext_tags_1[0]), /* 1 */
	asn_DEF_MeasurementControl_v3a0ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasurementControl_v3a0ext_tags_1)
		/sizeof(asn_DEF_MeasurementControl_v3a0ext_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasurementControl_v3a0ext_1,
	1,	/* Elements count */
	&asn_SPC_MeasurementControl_v3a0ext_specs_1	/* Additional specs */
};

