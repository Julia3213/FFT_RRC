/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UL-TransportChannelIdentity-r6.h"

static asn_oer_constraints_t asn_OER_type_UL_TransportChannelIdentity_r6_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_UL_TransportChannelIdentity_r6_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_dch_usch_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity_r6__dch_usch, ul_TransportChannelType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_TrCH_Type,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-TransportChannelType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity_r6__dch_usch, ul_TransportChannelIdentity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-TransportChannelIdentity"
		},
};
static const ber_tlv_tag_t asn_DEF_dch_usch_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_dch_usch_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ul-TransportChannelType */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ul-TransportChannelIdentity */
};
static asn_SEQUENCE_specifics_t asn_SPC_dch_usch_specs_2 = {
	sizeof(struct UL_TransportChannelIdentity_r6__dch_usch),
	offsetof(struct UL_TransportChannelIdentity_r6__dch_usch, _asn_ctx),
	asn_MAP_dch_usch_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dch_usch_2 = {
	"dch-usch",
	"dch-usch",
	&asn_OP_SEQUENCE,
	asn_DEF_dch_usch_tags_2,
	sizeof(asn_DEF_dch_usch_tags_2)
		/sizeof(asn_DEF_dch_usch_tags_2[0]) - 1, /* 1 */
	asn_DEF_dch_usch_tags_2,	/* Same as above */
	sizeof(asn_DEF_dch_usch_tags_2)
		/sizeof(asn_DEF_dch_usch_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_dch_usch_2,
	2,	/* Elements count */
	&asn_SPC_dch_usch_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_UL_TransportChannelIdentity_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity_r6, choice.dch_usch),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_dch_usch_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dch-usch"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity_r6, choice.e_dch),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MAC_d_FlowIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"e-dch"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_UL_TransportChannelIdentity_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dch-usch */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* e-dch */
};
asn_CHOICE_specifics_t asn_SPC_UL_TransportChannelIdentity_r6_specs_1 = {
	sizeof(struct UL_TransportChannelIdentity_r6),
	offsetof(struct UL_TransportChannelIdentity_r6, _asn_ctx),
	offsetof(struct UL_TransportChannelIdentity_r6, present),
	sizeof(((struct UL_TransportChannelIdentity_r6 *)0)->present),
	asn_MAP_UL_TransportChannelIdentity_r6_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UL_TransportChannelIdentity_r6 = {
	"UL-TransportChannelIdentity-r6",
	"UL-TransportChannelIdentity-r6",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_UL_TransportChannelIdentity_r6_constr_1, &asn_PER_type_UL_TransportChannelIdentity_r6_constr_1, CHOICE_constraint },
	asn_MBR_UL_TransportChannelIdentity_r6_1,
	2,	/* Elements count */
	&asn_SPC_UL_TransportChannelIdentity_r6_specs_1	/* Additional specs */
};

