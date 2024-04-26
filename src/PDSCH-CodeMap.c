/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PDSCH-CodeMap.h"

asn_TYPE_member_t asn_MBR_PDSCH_CodeMap_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDSCH_CodeMap, spreadingFactor),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SF_PDSCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spreadingFactor"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDSCH_CodeMap, multiCodeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MultiCodeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"multiCodeInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDSCH_CodeMap, codeNumberStart),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CodeNumberDSCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"codeNumberStart"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDSCH_CodeMap, codeNumberStop),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CodeNumberDSCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"codeNumberStop"
		},
};
static const ber_tlv_tag_t asn_DEF_PDSCH_CodeMap_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PDSCH_CodeMap_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* spreadingFactor */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* multiCodeInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* codeNumberStart */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* codeNumberStop */
};
asn_SEQUENCE_specifics_t asn_SPC_PDSCH_CodeMap_specs_1 = {
	sizeof(struct PDSCH_CodeMap),
	offsetof(struct PDSCH_CodeMap, _asn_ctx),
	asn_MAP_PDSCH_CodeMap_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PDSCH_CodeMap = {
	"PDSCH-CodeMap",
	"PDSCH-CodeMap",
	&asn_OP_SEQUENCE,
	asn_DEF_PDSCH_CodeMap_tags_1,
	sizeof(asn_DEF_PDSCH_CodeMap_tags_1)
		/sizeof(asn_DEF_PDSCH_CodeMap_tags_1[0]), /* 1 */
	asn_DEF_PDSCH_CodeMap_tags_1,	/* Same as above */
	sizeof(asn_DEF_PDSCH_CodeMap_tags_1)
		/sizeof(asn_DEF_PDSCH_CodeMap_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PDSCH_CodeMap_1,
	4,	/* Elements count */
	&asn_SPC_PDSCH_CodeMap_specs_1	/* Additional specs */
};
