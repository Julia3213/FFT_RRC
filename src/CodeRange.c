/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CodeRange.h"

asn_TYPE_member_t asn_MBR_CodeRange_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CodeRange, pdsch_CodeMapList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PDSCH_CodeMapList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pdsch-CodeMapList"
		},
};
static const ber_tlv_tag_t asn_DEF_CodeRange_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CodeRange_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* pdsch-CodeMapList */
};
asn_SEQUENCE_specifics_t asn_SPC_CodeRange_specs_1 = {
	sizeof(struct CodeRange),
	offsetof(struct CodeRange, _asn_ctx),
	asn_MAP_CodeRange_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CodeRange = {
	"CodeRange",
	"CodeRange",
	&asn_OP_SEQUENCE,
	asn_DEF_CodeRange_tags_1,
	sizeof(asn_DEF_CodeRange_tags_1)
		/sizeof(asn_DEF_CodeRange_tags_1[0]), /* 1 */
	asn_DEF_CodeRange_tags_1,	/* Same as above */
	sizeof(asn_DEF_CodeRange_tags_1)
		/sizeof(asn_DEF_CodeRange_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CodeRange_1,
	1,	/* Elements count */
	&asn_SPC_CodeRange_specs_1	/* Additional specs */
};

