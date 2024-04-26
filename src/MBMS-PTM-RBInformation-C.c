/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-PTM-RBInformation-C.h"

asn_TYPE_member_t asn_MBR_MBMS_PTM_RBInformation_C_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_PTM_RBInformation_C, rbInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_CommonRBIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rbInformation"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_PTM_RBInformation_C, shortTransmissionID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ShortTransmissionID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"shortTransmissionID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_PTM_RBInformation_C, logicalChIdentity),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_LogicalChIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"logicalChIdentity"
		},
};
static const ber_tlv_tag_t asn_DEF_MBMS_PTM_RBInformation_C_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMS_PTM_RBInformation_C_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rbInformation */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* shortTransmissionID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* logicalChIdentity */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMS_PTM_RBInformation_C_specs_1 = {
	sizeof(struct MBMS_PTM_RBInformation_C),
	offsetof(struct MBMS_PTM_RBInformation_C, _asn_ctx),
	asn_MAP_MBMS_PTM_RBInformation_C_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_PTM_RBInformation_C = {
	"MBMS-PTM-RBInformation-C",
	"MBMS-PTM-RBInformation-C",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMS_PTM_RBInformation_C_tags_1,
	sizeof(asn_DEF_MBMS_PTM_RBInformation_C_tags_1)
		/sizeof(asn_DEF_MBMS_PTM_RBInformation_C_tags_1[0]), /* 1 */
	asn_DEF_MBMS_PTM_RBInformation_C_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_PTM_RBInformation_C_tags_1)
		/sizeof(asn_DEF_MBMS_PTM_RBInformation_C_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMS_PTM_RBInformation_C_1,
	3,	/* Elements count */
	&asn_SPC_MBMS_PTM_RBInformation_C_specs_1	/* Additional specs */
};
