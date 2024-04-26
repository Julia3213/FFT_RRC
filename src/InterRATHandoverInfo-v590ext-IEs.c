/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "InterRATHandoverInfo-v590ext-IEs.h"

#include "PredefinedConfigStatusListComp.h"
#include "UE-RadioAccessCapabilityComp.h"
asn_TYPE_member_t asn_MBR_InterRATHandoverInfo_v590ext_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct InterRATHandoverInfo_v590ext_IEs, predefinedConfigStatusListComp),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PredefinedConfigStatusListComp,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"predefinedConfigStatusListComp"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATHandoverInfo_v590ext_IEs, ue_RadioAccessCapabilityComp),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_RadioAccessCapabilityComp,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-RadioAccessCapabilityComp"
		},
};
static const int asn_MAP_InterRATHandoverInfo_v590ext_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterRATHandoverInfo_v590ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* predefinedConfigStatusListComp */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ue-RadioAccessCapabilityComp */
};
asn_SEQUENCE_specifics_t asn_SPC_InterRATHandoverInfo_v590ext_IEs_specs_1 = {
	sizeof(struct InterRATHandoverInfo_v590ext_IEs),
	offsetof(struct InterRATHandoverInfo_v590ext_IEs, _asn_ctx),
	asn_MAP_InterRATHandoverInfo_v590ext_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_InterRATHandoverInfo_v590ext_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfo_v590ext_IEs = {
	"InterRATHandoverInfo-v590ext-IEs",
	"InterRATHandoverInfo-v590ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1,
	sizeof(asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfo_v590ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InterRATHandoverInfo_v590ext_IEs_1,
	2,	/* Elements count */
	&asn_SPC_InterRATHandoverInfo_v590ext_IEs_specs_1	/* Additional specs */
};
