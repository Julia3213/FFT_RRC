/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-PhysChCapabilityTDD-768.h"

asn_TYPE_member_t asn_MBR_DL_PhysChCapabilityTDD_768_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityTDD_768, maxTS_PerFrame),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxTS_PerFrame,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxTS-PerFrame"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityTDD_768, maxPhysChPerFrame),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxPhysChPerFrame_768,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxPhysChPerFrame"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityTDD_768, minimumSF),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MinimumSF_DL_768,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"minimumSF"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityTDD_768, supportOfPDSCH),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"supportOfPDSCH"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_PhysChCapabilityTDD_768, maxPhysChPerTS),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxPhysChPerTS_768,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxPhysChPerTS"
		},
};
static const ber_tlv_tag_t asn_DEF_DL_PhysChCapabilityTDD_768_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_PhysChCapabilityTDD_768_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxTS-PerFrame */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* maxPhysChPerFrame */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* minimumSF */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* supportOfPDSCH */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* maxPhysChPerTS */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_PhysChCapabilityTDD_768_specs_1 = {
	sizeof(struct DL_PhysChCapabilityTDD_768),
	offsetof(struct DL_PhysChCapabilityTDD_768, _asn_ctx),
	asn_MAP_DL_PhysChCapabilityTDD_768_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_PhysChCapabilityTDD_768 = {
	"DL-PhysChCapabilityTDD-768",
	"DL-PhysChCapabilityTDD-768",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_PhysChCapabilityTDD_768_tags_1,
	sizeof(asn_DEF_DL_PhysChCapabilityTDD_768_tags_1)
		/sizeof(asn_DEF_DL_PhysChCapabilityTDD_768_tags_1[0]), /* 1 */
	asn_DEF_DL_PhysChCapabilityTDD_768_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_PhysChCapabilityTDD_768_tags_1)
		/sizeof(asn_DEF_DL_PhysChCapabilityTDD_768_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_PhysChCapabilityTDD_768_1,
	5,	/* Elements count */
	&asn_SPC_DL_PhysChCapabilityTDD_768_specs_1	/* Additional specs */
};

