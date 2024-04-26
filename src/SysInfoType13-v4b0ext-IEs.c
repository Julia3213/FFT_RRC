/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SysInfoType13-v4b0ext-IEs.h"

#include "CapabilityUpdateRequirement-r4-ext.h"
asn_TYPE_member_t asn_MBR_SysInfoType13_v4b0ext_IEs_1[] = {
	{ ATF_POINTER, 1, offsetof(struct SysInfoType13_v4b0ext_IEs, capabilityUpdateRequirement_r4Ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CapabilityUpdateRequirement_r4_ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"capabilityUpdateRequirement-r4Ext"
		},
};
static const int asn_MAP_SysInfoType13_v4b0ext_IEs_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SysInfoType13_v4b0ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* capabilityUpdateRequirement-r4Ext */
};
asn_SEQUENCE_specifics_t asn_SPC_SysInfoType13_v4b0ext_IEs_specs_1 = {
	sizeof(struct SysInfoType13_v4b0ext_IEs),
	offsetof(struct SysInfoType13_v4b0ext_IEs, _asn_ctx),
	asn_MAP_SysInfoType13_v4b0ext_IEs_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_SysInfoType13_v4b0ext_IEs_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SysInfoType13_v4b0ext_IEs = {
	"SysInfoType13-v4b0ext-IEs",
	"SysInfoType13-v4b0ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1,
	sizeof(asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1)
		/sizeof(asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1)
		/sizeof(asn_DEF_SysInfoType13_v4b0ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SysInfoType13_v4b0ext_IEs_1,
	1,	/* Elements count */
	&asn_SPC_SysInfoType13_v4b0ext_IEs_specs_1	/* Additional specs */
};

