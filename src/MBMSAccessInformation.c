/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMSAccessInformation.h"

static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_3 = {
	sizeof(struct MBMSAccessInformation__nonCriticalExtensions),
	offsetof(struct MBMSAccessInformation__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_3 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_3,
	sizeof(asn_DEF_nonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_3[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_3,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_MBMSAccessInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBMSAccessInformation, mbms_ServiceAccessInfoList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBMS_ServiceAccessInfoList_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mbms-ServiceAccessInfoList"
		},
	{ ATF_POINTER, 1, offsetof(struct MBMSAccessInformation, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_MBMSAccessInformation_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_MBMSAccessInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MBMSAccessInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbms-ServiceAccessInfoList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
asn_SEQUENCE_specifics_t asn_SPC_MBMSAccessInformation_specs_1 = {
	sizeof(struct MBMSAccessInformation),
	offsetof(struct MBMSAccessInformation, _asn_ctx),
	asn_MAP_MBMSAccessInformation_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_MBMSAccessInformation_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MBMSAccessInformation = {
	"MBMSAccessInformation",
	"MBMSAccessInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_MBMSAccessInformation_tags_1,
	sizeof(asn_DEF_MBMSAccessInformation_tags_1)
		/sizeof(asn_DEF_MBMSAccessInformation_tags_1[0]), /* 1 */
	asn_DEF_MBMSAccessInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMSAccessInformation_tags_1)
		/sizeof(asn_DEF_MBMSAccessInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MBMSAccessInformation_1,
	2,	/* Elements count */
	&asn_SPC_MBMSAccessInformation_specs_1	/* Additional specs */
};
