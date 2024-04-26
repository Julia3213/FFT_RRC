/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TGP-Sequence.h"

#include "TGPS-ConfigurationParams.h"
static asn_oer_constraints_t asn_OER_type_tgps_Status_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_tgps_Status_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_activate_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TGP_Sequence__tgps_Status__activate, tgcfn),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TGCFN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tgcfn"
		},
};
static const ber_tlv_tag_t asn_DEF_activate_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_activate_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* tgcfn */
};
static asn_SEQUENCE_specifics_t asn_SPC_activate_specs_4 = {
	sizeof(struct TGP_Sequence__tgps_Status__activate),
	offsetof(struct TGP_Sequence__tgps_Status__activate, _asn_ctx),
	asn_MAP_activate_tag2el_4,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_activate_4 = {
	"activate",
	"activate",
	&asn_OP_SEQUENCE,
	asn_DEF_activate_tags_4,
	sizeof(asn_DEF_activate_tags_4)
		/sizeof(asn_DEF_activate_tags_4[0]) - 1, /* 1 */
	asn_DEF_activate_tags_4,	/* Same as above */
	sizeof(asn_DEF_activate_tags_4)
		/sizeof(asn_DEF_activate_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_activate_4,
	1,	/* Elements count */
	&asn_SPC_activate_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tgps_Status_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TGP_Sequence__tgps_Status, choice.activate),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_activate_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"activate"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TGP_Sequence__tgps_Status, choice.deactivate),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deactivate"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_tgps_Status_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* activate */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* deactivate */
};
static asn_CHOICE_specifics_t asn_SPC_tgps_Status_specs_3 = {
	sizeof(struct TGP_Sequence__tgps_Status),
	offsetof(struct TGP_Sequence__tgps_Status, _asn_ctx),
	offsetof(struct TGP_Sequence__tgps_Status, present),
	sizeof(((struct TGP_Sequence__tgps_Status *)0)->present),
	asn_MAP_tgps_Status_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tgps_Status_3 = {
	"tgps-Status",
	"tgps-Status",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_tgps_Status_constr_3, &asn_PER_type_tgps_Status_constr_3, CHOICE_constraint },
	asn_MBR_tgps_Status_3,
	2,	/* Elements count */
	&asn_SPC_tgps_Status_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_TGP_Sequence_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TGP_Sequence, tgpsi),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TGPSI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tgpsi"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TGP_Sequence, tgps_Status),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tgps_Status_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tgps-Status"
		},
	{ ATF_POINTER, 1, offsetof(struct TGP_Sequence, tgps_ConfigurationParams),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TGPS_ConfigurationParams,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tgps-ConfigurationParams"
		},
};
static const int asn_MAP_TGP_Sequence_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_TGP_Sequence_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TGP_Sequence_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* tgpsi */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tgps-Status */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* tgps-ConfigurationParams */
};
asn_SEQUENCE_specifics_t asn_SPC_TGP_Sequence_specs_1 = {
	sizeof(struct TGP_Sequence),
	offsetof(struct TGP_Sequence, _asn_ctx),
	asn_MAP_TGP_Sequence_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_TGP_Sequence_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_TGP_Sequence = {
	"TGP-Sequence",
	"TGP-Sequence",
	&asn_OP_SEQUENCE,
	asn_DEF_TGP_Sequence_tags_1,
	sizeof(asn_DEF_TGP_Sequence_tags_1)
		/sizeof(asn_DEF_TGP_Sequence_tags_1[0]), /* 1 */
	asn_DEF_TGP_Sequence_tags_1,	/* Same as above */
	sizeof(asn_DEF_TGP_Sequence_tags_1)
		/sizeof(asn_DEF_TGP_Sequence_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_TGP_Sequence_1,
	3,	/* Elements count */
	&asn_SPC_TGP_Sequence_specs_1	/* Additional specs */
};

