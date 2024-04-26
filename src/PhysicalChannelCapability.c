/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PhysicalChannelCapability.h"

static asn_TYPE_member_t asn_MBR_fddPhysChCapability_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability__fddPhysChCapability, downlinkPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_PhysChCapabilityFDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"downlinkPhysChCapability"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability__fddPhysChCapability, uplinkPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_PhysChCapabilityFDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uplinkPhysChCapability"
		},
};
static const ber_tlv_tag_t asn_DEF_fddPhysChCapability_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fddPhysChCapability_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* downlinkPhysChCapability */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* uplinkPhysChCapability */
};
static asn_SEQUENCE_specifics_t asn_SPC_fddPhysChCapability_specs_2 = {
	sizeof(struct PhysicalChannelCapability__fddPhysChCapability),
	offsetof(struct PhysicalChannelCapability__fddPhysChCapability, _asn_ctx),
	asn_MAP_fddPhysChCapability_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fddPhysChCapability_2 = {
	"fddPhysChCapability",
	"fddPhysChCapability",
	&asn_OP_SEQUENCE,
	asn_DEF_fddPhysChCapability_tags_2,
	sizeof(asn_DEF_fddPhysChCapability_tags_2)
		/sizeof(asn_DEF_fddPhysChCapability_tags_2[0]) - 1, /* 1 */
	asn_DEF_fddPhysChCapability_tags_2,	/* Same as above */
	sizeof(asn_DEF_fddPhysChCapability_tags_2)
		/sizeof(asn_DEF_fddPhysChCapability_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fddPhysChCapability_2,
	2,	/* Elements count */
	&asn_SPC_fddPhysChCapability_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tddPhysChCapability_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability__tddPhysChCapability, downlinkPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_PhysChCapabilityTDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"downlinkPhysChCapability"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability__tddPhysChCapability, uplinkPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_PhysChCapabilityTDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uplinkPhysChCapability"
		},
};
static const ber_tlv_tag_t asn_DEF_tddPhysChCapability_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tddPhysChCapability_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* downlinkPhysChCapability */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* uplinkPhysChCapability */
};
static asn_SEQUENCE_specifics_t asn_SPC_tddPhysChCapability_specs_5 = {
	sizeof(struct PhysicalChannelCapability__tddPhysChCapability),
	offsetof(struct PhysicalChannelCapability__tddPhysChCapability, _asn_ctx),
	asn_MAP_tddPhysChCapability_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tddPhysChCapability_5 = {
	"tddPhysChCapability",
	"tddPhysChCapability",
	&asn_OP_SEQUENCE,
	asn_DEF_tddPhysChCapability_tags_5,
	sizeof(asn_DEF_tddPhysChCapability_tags_5)
		/sizeof(asn_DEF_tddPhysChCapability_tags_5[0]) - 1, /* 1 */
	asn_DEF_tddPhysChCapability_tags_5,	/* Same as above */
	sizeof(asn_DEF_tddPhysChCapability_tags_5)
		/sizeof(asn_DEF_tddPhysChCapability_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tddPhysChCapability_5,
	2,	/* Elements count */
	&asn_SPC_tddPhysChCapability_specs_5	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_PhysicalChannelCapability_1[] = {
	{ ATF_POINTER, 2, offsetof(struct PhysicalChannelCapability, fddPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fddPhysChCapability_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fddPhysChCapability"
		},
	{ ATF_POINTER, 1, offsetof(struct PhysicalChannelCapability, tddPhysChCapability),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tddPhysChCapability_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tddPhysChCapability"
		},
};
static const int asn_MAP_PhysicalChannelCapability_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_PhysicalChannelCapability_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PhysicalChannelCapability_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fddPhysChCapability */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tddPhysChCapability */
};
asn_SEQUENCE_specifics_t asn_SPC_PhysicalChannelCapability_specs_1 = {
	sizeof(struct PhysicalChannelCapability),
	offsetof(struct PhysicalChannelCapability, _asn_ctx),
	asn_MAP_PhysicalChannelCapability_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_PhysicalChannelCapability_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PhysicalChannelCapability = {
	"PhysicalChannelCapability",
	"PhysicalChannelCapability",
	&asn_OP_SEQUENCE,
	asn_DEF_PhysicalChannelCapability_tags_1,
	sizeof(asn_DEF_PhysicalChannelCapability_tags_1)
		/sizeof(asn_DEF_PhysicalChannelCapability_tags_1[0]), /* 1 */
	asn_DEF_PhysicalChannelCapability_tags_1,	/* Same as above */
	sizeof(asn_DEF_PhysicalChannelCapability_tags_1)
		/sizeof(asn_DEF_PhysicalChannelCapability_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PhysicalChannelCapability_1,
	2,	/* Elements count */
	&asn_SPC_PhysicalChannelCapability_specs_1	/* Additional specs */
};

