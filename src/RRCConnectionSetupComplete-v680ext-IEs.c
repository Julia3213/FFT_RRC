/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RRCConnectionSetupComplete-v680ext-IEs.h"

asn_TYPE_member_t asn_MBR_RRCConnectionSetupComplete_v680ext_IEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetupComplete_v680ext_IEs, ue_RadioAccessCapability_v680ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_RadioAccessCapability_v680ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-RadioAccessCapability-v680ext"
		},
};
static const ber_tlv_tag_t asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RRCConnectionSetupComplete_v680ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* ue-RadioAccessCapability-v680ext */
};
asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetupComplete_v680ext_IEs_specs_1 = {
	sizeof(struct RRCConnectionSetupComplete_v680ext_IEs),
	offsetof(struct RRCConnectionSetupComplete_v680ext_IEs, _asn_ctx),
	asn_MAP_RRCConnectionSetupComplete_v680ext_IEs_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetupComplete_v680ext_IEs = {
	"RRCConnectionSetupComplete-v680ext-IEs",
	"RRCConnectionSetupComplete-v680ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1,
	sizeof(asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetupComplete_v680ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RRCConnectionSetupComplete_v680ext_IEs_1,
	1,	/* Elements count */
	&asn_SPC_RRCConnectionSetupComplete_v680ext_IEs_specs_1	/* Additional specs */
};

