/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TargetRNC-ToSourceRNC-Container.h"

static asn_oer_constraints_t asn_OER_type_TargetRNC_ToSourceRNC_Container_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_TargetRNC_ToSourceRNC_Container_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_TargetRNC_ToSourceRNC_Container_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.radioBearerSetup),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RadioBearerSetup,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioBearerSetup"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.radioBearerReconfiguration),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RadioBearerReconfiguration,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioBearerReconfiguration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.radioBearerRelease),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RadioBearerRelease,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioBearerRelease"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.transportChannelReconfiguration),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TransportChannelReconfiguration,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transportChannelReconfiguration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.physicalChannelReconfiguration),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PhysicalChannelReconfiguration,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"physicalChannelReconfiguration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.rrc_FailureInfo),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RRC_FailureInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrc-FailureInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.dL_DCCHmessage),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dL-DCCHmessage"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TargetRNC_ToSourceRNC_Container, choice.extension),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"extension"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_TargetRNC_ToSourceRNC_Container_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* radioBearerSetup */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* radioBearerReconfiguration */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* radioBearerRelease */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* transportChannelReconfiguration */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* physicalChannelReconfiguration */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* rrc-FailureInfo */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* dL-DCCHmessage */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* extension */
};
static asn_CHOICE_specifics_t asn_SPC_TargetRNC_ToSourceRNC_Container_specs_1 = {
	sizeof(struct TargetRNC_ToSourceRNC_Container),
	offsetof(struct TargetRNC_ToSourceRNC_Container, _asn_ctx),
	offsetof(struct TargetRNC_ToSourceRNC_Container, present),
	sizeof(((struct TargetRNC_ToSourceRNC_Container *)0)->present),
	asn_MAP_TargetRNC_ToSourceRNC_Container_tag2el_1,
	8,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_TargetRNC_ToSourceRNC_Container = {
	"TargetRNC-ToSourceRNC-Container",
	"TargetRNC-ToSourceRNC-Container",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_TargetRNC_ToSourceRNC_Container_constr_1, &asn_PER_type_TargetRNC_ToSourceRNC_Container_constr_1, CHOICE_constraint },
	asn_MBR_TargetRNC_ToSourceRNC_Container_1,
	8,	/* Elements count */
	&asn_SPC_TargetRNC_ToSourceRNC_Container_specs_1	/* Additional specs */
};
