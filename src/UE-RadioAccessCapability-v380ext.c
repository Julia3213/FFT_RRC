/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-RadioAccessCapability-v380ext.h"

asn_TYPE_member_t asn_MBR_UE_RadioAccessCapability_v380ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_RadioAccessCapability_v380ext, ue_PositioningCapabilityExt_v380),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_PositioningCapabilityExt_v380,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-PositioningCapabilityExt-v380"
		},
};
static const ber_tlv_tag_t asn_DEF_UE_RadioAccessCapability_v380ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_RadioAccessCapability_v380ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* ue-PositioningCapabilityExt-v380 */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapability_v380ext_specs_1 = {
	sizeof(struct UE_RadioAccessCapability_v380ext),
	offsetof(struct UE_RadioAccessCapability_v380ext, _asn_ctx),
	asn_MAP_UE_RadioAccessCapability_v380ext_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapability_v380ext = {
	"UE-RadioAccessCapability-v380ext",
	"UE-RadioAccessCapability-v380ext",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_RadioAccessCapability_v380ext_tags_1,
	sizeof(asn_DEF_UE_RadioAccessCapability_v380ext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapability_v380ext_tags_1[0]), /* 1 */
	asn_DEF_UE_RadioAccessCapability_v380ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_RadioAccessCapability_v380ext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapability_v380ext_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_RadioAccessCapability_v380ext_1,
	1,	/* Elements count */
	&asn_SPC_UE_RadioAccessCapability_v380ext_specs_1	/* Additional specs */
};

