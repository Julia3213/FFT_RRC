/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RRCConnectionSetupComplete-r3-add-ext-IEs.h"

#include "RRCConnectionSetupComplete-v650ext-IEs.h"
static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_5 = {
	sizeof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_5 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_5,
	sizeof(asn_DEF_nonCriticalExtensions_tags_5)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_5[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_5,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_5)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v680NonCriticalExtensions_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions, rrcConnectionSetupComplete_v680ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRCConnectionSetupComplete_v680ext_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrcConnectionSetupComplete-v680ext"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_v680NonCriticalExtensions_oms_3[] = { 1 };
static const ber_tlv_tag_t asn_DEF_v680NonCriticalExtensions_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_v680NonCriticalExtensions_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrcConnectionSetupComplete-v680ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_v680NonCriticalExtensions_specs_3 = {
	sizeof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions),
	offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs__v680NonCriticalExtensions, _asn_ctx),
	asn_MAP_v680NonCriticalExtensions_tag2el_3,
	2,	/* Count of tags in the map */
	asn_MAP_v680NonCriticalExtensions_oms_3,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v680NonCriticalExtensions_3 = {
	"v680NonCriticalExtensions",
	"v680NonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_v680NonCriticalExtensions_tags_3,
	sizeof(asn_DEF_v680NonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_v680NonCriticalExtensions_tags_3[0]) - 1, /* 1 */
	asn_DEF_v680NonCriticalExtensions_tags_3,	/* Same as above */
	sizeof(asn_DEF_v680NonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_v680NonCriticalExtensions_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_v680NonCriticalExtensions_3,
	2,	/* Elements count */
	&asn_SPC_v680NonCriticalExtensions_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_RRCConnectionSetupComplete_r3_add_ext_IEs_1[] = {
	{ ATF_POINTER, 2, offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs, rrcConnectionSetupComplete_v650ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRCConnectionSetupComplete_v650ext_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rrcConnectionSetupComplete-v650ext"
		},
	{ ATF_POINTER, 1, offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs, v680NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v680NonCriticalExtensions_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"v680NonCriticalExtensions"
		},
};
static const int asn_MAP_RRCConnectionSetupComplete_r3_add_ext_IEs_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RRCConnectionSetupComplete_r3_add_ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrcConnectionSetupComplete-v650ext */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v680NonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_RRCConnectionSetupComplete_r3_add_ext_IEs_specs_1 = {
	sizeof(struct RRCConnectionSetupComplete_r3_add_ext_IEs),
	offsetof(struct RRCConnectionSetupComplete_r3_add_ext_IEs, _asn_ctx),
	asn_MAP_RRCConnectionSetupComplete_r3_add_ext_IEs_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_RRCConnectionSetupComplete_r3_add_ext_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs = {
	"RRCConnectionSetupComplete-r3-add-ext-IEs",
	"RRCConnectionSetupComplete-r3-add-ext-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1,
	sizeof(asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1)
		/sizeof(asn_DEF_RRCConnectionSetupComplete_r3_add_ext_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RRCConnectionSetupComplete_r3_add_ext_IEs_1,
	2,	/* Elements count */
	&asn_SPC_RRCConnectionSetupComplete_r3_add_ext_IEs_specs_1	/* Additional specs */
};

