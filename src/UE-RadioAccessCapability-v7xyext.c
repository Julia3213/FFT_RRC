/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-RadioAccessCapability-v7xyext.h"

#include "RF-Capability-r7.h"
#include "PhysicalChannelCapability-r7.h"
asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_v7xyext_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UE_RadioAccessCapability_v7xyext, rf_Capability),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RF_Capability_r7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rf-Capability"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_RadioAccessCapability_v7xyext, physicalChannelCapability_r7),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PhysicalChannelCapability_r7,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"physicalChannelCapability-r7"
		},
};
static const int asn_MAP_UE_RadioAccessCapability_v7xyext_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_RadioAccessCapability_v7xyext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rf-Capability */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* physicalChannelCapability-r7 */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_v7xyext_specs_1 = {
	sizeof(struct UE_RadioAccessCapability_v7xyext),
	offsetof(struct UE_RadioAccessCapability_v7xyext, _asn_ctx),
	asn_MAP_UE_RadioAccessCapability_v7xyext_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UE_RadioAccessCapability_v7xyext_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_v7xyext = {
	"UE-RadioAccessCapability-v7xyext",
	"UE-RadioAccessCapability-v7xyext",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1,
	sizeof(asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1[0]), /* 1 */
	asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapability_v7xyext_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_RadioAccessCapability_v7xyext_1,
	2,	/* Elements count */
	&asn_SPC_UE_RadioAccessCapability_v7xyext_specs_1	/* Additional specs */
};
