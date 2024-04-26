/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-ServiceAccessInfo-r6.h"

asn_TYPE_member_t asn_MBR_MBMS_ServiceAccessInfo_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_ServiceAccessInfo_r6, shortTransmissionID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ShortTransmissionID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"shortTransmissionID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_ServiceAccessInfo_r6, accessprobabilityFactor_Idle),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_AccessProbabilityFactor,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"accessprobabilityFactor-Idle"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMS_ServiceAccessInfo_r6, accessprobabilityFactor_UraPCH),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_AccessProbabilityFactor,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"accessprobabilityFactor-UraPCH"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBMS_ServiceAccessInfo_r6, mbms_ConnectedModeCountingScope),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ConnectedModeCountingScope,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-ConnectedModeCountingScope"
		},
};
static const int asn_MAP_MBMS_ServiceAccessInfo_r6_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMS_ServiceAccessInfo_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* shortTransmissionID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* accessprobabilityFactor-Idle */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* accessprobabilityFactor-UraPCH */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* mbms-ConnectedModeCountingScope */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMS_ServiceAccessInfo_r6_specs_1 = {
	sizeof(struct MBMS_ServiceAccessInfo_r6),
	offsetof(struct MBMS_ServiceAccessInfo_r6, _asn_ctx),
	asn_MAP_MBMS_ServiceAccessInfo_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_MBMS_ServiceAccessInfo_r6_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMS_ServiceAccessInfo_r6 = {
	"MBMS-ServiceAccessInfo-r6",
	"MBMS-ServiceAccessInfo-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1,
	sizeof(asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1)
		/sizeof(asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1[0]), /* 1 */
	asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1)
		/sizeof(asn_DEF_MBMS_ServiceAccessInfo_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMS_ServiceAccessInfo_r6_1,
	4,	/* Elements count */
	&asn_SPC_MBMS_ServiceAccessInfo_r6_specs_1	/* Additional specs */
};
