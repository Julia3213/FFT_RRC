/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SRNC-RelocationInfo-v3d0ext-IEs.h"

asn_TYPE_member_t asn_MBR_SRNC_RelocationInfo_v3d0ext_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct SRNC_RelocationInfo_v3d0ext_IEs, uESpecificBehaviourInformation1idle),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UESpecificBehaviourInformation1idle,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uESpecificBehaviourInformation1idle"
		},
	{ ATF_POINTER, 1, offsetof(struct SRNC_RelocationInfo_v3d0ext_IEs, uESpecificBehaviourInformation1interRAT),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UESpecificBehaviourInformation1interRAT,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uESpecificBehaviourInformation1interRAT"
		},
};
static const int asn_MAP_SRNC_RelocationInfo_v3d0ext_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SRNC_RelocationInfo_v3d0ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* uESpecificBehaviourInformation1idle */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* uESpecificBehaviourInformation1interRAT */
};
asn_SEQUENCE_specifics_t asn_SPC_SRNC_RelocationInfo_v3d0ext_IEs_specs_1 = {
	sizeof(struct SRNC_RelocationInfo_v3d0ext_IEs),
	offsetof(struct SRNC_RelocationInfo_v3d0ext_IEs, _asn_ctx),
	asn_MAP_SRNC_RelocationInfo_v3d0ext_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SRNC_RelocationInfo_v3d0ext_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs = {
	"SRNC-RelocationInfo-v3d0ext-IEs",
	"SRNC-RelocationInfo-v3d0ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1,
	sizeof(asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1)
		/sizeof(asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1)
		/sizeof(asn_DEF_SRNC_RelocationInfo_v3d0ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SRNC_RelocationInfo_v3d0ext_IEs_1,
	2,	/* Elements count */
	&asn_SPC_SRNC_RelocationInfo_v3d0ext_IEs_specs_1	/* Additional specs */
};

