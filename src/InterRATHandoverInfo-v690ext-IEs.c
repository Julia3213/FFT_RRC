/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "InterRATHandoverInfo-v690ext-IEs.h"

#include "UE-SecurityInformation2.h"
#include "UE-RadioAccessCapabilityComp-ext.h"
asn_TYPE_member_t asn_MBR_InterRATHandoverInfo_v690ext_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct InterRATHandoverInfo_v690ext_IEs, ue_SecurityInformation2),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_SecurityInformation2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-SecurityInformation2"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATHandoverInfo_v690ext_IEs, ue_RadioAccessCapabilityComp),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_RadioAccessCapabilityComp_ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-RadioAccessCapabilityComp"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATHandoverInfo_v690ext_IEs, ue_RadioAccessCapabilityComp2),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_RadioAccessCapabilityComp2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-RadioAccessCapabilityComp2"
		},
};
static const int asn_MAP_InterRATHandoverInfo_v690ext_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterRATHandoverInfo_v690ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ue-SecurityInformation2 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ue-RadioAccessCapabilityComp */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ue-RadioAccessCapabilityComp2 */
};
asn_SEQUENCE_specifics_t asn_SPC_InterRATHandoverInfo_v690ext_IEs_specs_1 = {
	sizeof(struct InterRATHandoverInfo_v690ext_IEs),
	offsetof(struct InterRATHandoverInfo_v690ext_IEs, _asn_ctx),
	asn_MAP_InterRATHandoverInfo_v690ext_IEs_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_InterRATHandoverInfo_v690ext_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfo_v690ext_IEs = {
	"InterRATHandoverInfo-v690ext-IEs",
	"InterRATHandoverInfo-v690ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1,
	sizeof(asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfo_v690ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InterRATHandoverInfo_v690ext_IEs_1,
	3,	/* Elements count */
	&asn_SPC_InterRATHandoverInfo_v690ext_IEs_specs_1	/* Additional specs */
};
