/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "IntegrityProtectionModeCommand.h"

static asn_oer_constraints_t asn_OER_type_IntegrityProtectionModeCommand_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_IntegrityProtectionModeCommand_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_startIntegrityProtection_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IntegrityProtectionModeCommand__startIntegrityProtection, integrityProtInitNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtInitNumber,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"integrityProtInitNumber"
		},
};
static const ber_tlv_tag_t asn_DEF_startIntegrityProtection_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_startIntegrityProtection_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* integrityProtInitNumber */
};
static asn_SEQUENCE_specifics_t asn_SPC_startIntegrityProtection_specs_2 = {
	sizeof(struct IntegrityProtectionModeCommand__startIntegrityProtection),
	offsetof(struct IntegrityProtectionModeCommand__startIntegrityProtection, _asn_ctx),
	asn_MAP_startIntegrityProtection_tag2el_2,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_startIntegrityProtection_2 = {
	"startIntegrityProtection",
	"startIntegrityProtection",
	&asn_OP_SEQUENCE,
	asn_DEF_startIntegrityProtection_tags_2,
	sizeof(asn_DEF_startIntegrityProtection_tags_2)
		/sizeof(asn_DEF_startIntegrityProtection_tags_2[0]) - 1, /* 1 */
	asn_DEF_startIntegrityProtection_tags_2,	/* Same as above */
	sizeof(asn_DEF_startIntegrityProtection_tags_2)
		/sizeof(asn_DEF_startIntegrityProtection_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_startIntegrityProtection_2,
	1,	/* Elements count */
	&asn_SPC_startIntegrityProtection_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modify_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IntegrityProtectionModeCommand__modify, dl_IntegrityProtActivationInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtActivationInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-IntegrityProtActivationInfo"
		},
};
static const ber_tlv_tag_t asn_DEF_modify_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_modify_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* dl-IntegrityProtActivationInfo */
};
static asn_SEQUENCE_specifics_t asn_SPC_modify_specs_4 = {
	sizeof(struct IntegrityProtectionModeCommand__modify),
	offsetof(struct IntegrityProtectionModeCommand__modify, _asn_ctx),
	asn_MAP_modify_tag2el_4,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modify_4 = {
	"modify",
	"modify",
	&asn_OP_SEQUENCE,
	asn_DEF_modify_tags_4,
	sizeof(asn_DEF_modify_tags_4)
		/sizeof(asn_DEF_modify_tags_4[0]) - 1, /* 1 */
	asn_DEF_modify_tags_4,	/* Same as above */
	sizeof(asn_DEF_modify_tags_4)
		/sizeof(asn_DEF_modify_tags_4[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_modify_4,
	1,	/* Elements count */
	&asn_SPC_modify_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_IntegrityProtectionModeCommand_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IntegrityProtectionModeCommand, choice.startIntegrityProtection),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_startIntegrityProtection_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"startIntegrityProtection"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntegrityProtectionModeCommand, choice.modify),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_modify_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"modify"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_IntegrityProtectionModeCommand_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* startIntegrityProtection */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* modify */
};
asn_CHOICE_specifics_t asn_SPC_IntegrityProtectionModeCommand_specs_1 = {
	sizeof(struct IntegrityProtectionModeCommand),
	offsetof(struct IntegrityProtectionModeCommand, _asn_ctx),
	offsetof(struct IntegrityProtectionModeCommand, present),
	sizeof(((struct IntegrityProtectionModeCommand *)0)->present),
	asn_MAP_IntegrityProtectionModeCommand_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_IntegrityProtectionModeCommand = {
	"IntegrityProtectionModeCommand",
	"IntegrityProtectionModeCommand",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_IntegrityProtectionModeCommand_constr_1, &asn_PER_type_IntegrityProtectionModeCommand_constr_1, CHOICE_constraint },
	asn_MBR_IntegrityProtectionModeCommand_1,
	2,	/* Elements count */
	&asn_SPC_IntegrityProtectionModeCommand_specs_1	/* Additional specs */
};
