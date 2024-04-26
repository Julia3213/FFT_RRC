/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DSCH-Mapping.h"

asn_TYPE_member_t asn_MBR_DSCH_Mapping_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DSCH_Mapping, maxTFCI_Field2Value),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxTFCI_Field2Value,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxTFCI-Field2Value"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DSCH_Mapping, spreadingFactor),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SF_PDSCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"spreadingFactor"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DSCH_Mapping, codeNumber),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CodeNumberDSCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"codeNumber"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DSCH_Mapping, multiCodeInfo),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MultiCodeInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"multiCodeInfo"
		},
};
static const ber_tlv_tag_t asn_DEF_DSCH_Mapping_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DSCH_Mapping_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxTFCI-Field2Value */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* spreadingFactor */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* codeNumber */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* multiCodeInfo */
};
asn_SEQUENCE_specifics_t asn_SPC_DSCH_Mapping_specs_1 = {
	sizeof(struct DSCH_Mapping),
	offsetof(struct DSCH_Mapping, _asn_ctx),
	asn_MAP_DSCH_Mapping_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DSCH_Mapping = {
	"DSCH-Mapping",
	"DSCH-Mapping",
	&asn_OP_SEQUENCE,
	asn_DEF_DSCH_Mapping_tags_1,
	sizeof(asn_DEF_DSCH_Mapping_tags_1)
		/sizeof(asn_DEF_DSCH_Mapping_tags_1[0]), /* 1 */
	asn_DEF_DSCH_Mapping_tags_1,	/* Same as above */
	sizeof(asn_DEF_DSCH_Mapping_tags_1)
		/sizeof(asn_DEF_DSCH_Mapping_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DSCH_Mapping_1,
	4,	/* Elements count */
	&asn_SPC_DSCH_Mapping_specs_1	/* Additional specs */
};
