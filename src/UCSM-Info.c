/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UCSM-Info.h"

asn_TYPE_member_t asn_MBR_UCSM_Info_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UCSM_Info, minimumSpreadingFactor),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MinimumSpreadingFactor,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"minimumSpreadingFactor"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UCSM_Info, nf_Max),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NF_Max,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nf-Max"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UCSM_Info, channelReqParamsForUCSM),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ChannelReqParamsForUCSM,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"channelReqParamsForUCSM"
		},
};
static const ber_tlv_tag_t asn_DEF_UCSM_Info_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UCSM_Info_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* minimumSpreadingFactor */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* nf-Max */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* channelReqParamsForUCSM */
};
asn_SEQUENCE_specifics_t asn_SPC_UCSM_Info_specs_1 = {
	sizeof(struct UCSM_Info),
	offsetof(struct UCSM_Info, _asn_ctx),
	asn_MAP_UCSM_Info_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UCSM_Info = {
	"UCSM-Info",
	"UCSM-Info",
	&asn_OP_SEQUENCE,
	asn_DEF_UCSM_Info_tags_1,
	sizeof(asn_DEF_UCSM_Info_tags_1)
		/sizeof(asn_DEF_UCSM_Info_tags_1[0]), /* 1 */
	asn_DEF_UCSM_Info_tags_1,	/* Same as above */
	sizeof(asn_DEF_UCSM_Info_tags_1)
		/sizeof(asn_DEF_UCSM_Info_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UCSM_Info_1,
	3,	/* Elements count */
	&asn_SPC_UCSM_Info_specs_1	/* Additional specs */
};

