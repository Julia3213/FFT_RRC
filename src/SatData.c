/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SatData.h"

asn_TYPE_member_t asn_MBR_SatData_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SatData, satID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SatID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"satID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SatData, iode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IODE,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iode"
		},
};
static const ber_tlv_tag_t asn_DEF_SatData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SatData_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* satID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* iode */
};
asn_SEQUENCE_specifics_t asn_SPC_SatData_specs_1 = {
	sizeof(struct SatData),
	offsetof(struct SatData, _asn_ctx),
	asn_MAP_SatData_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SatData = {
	"SatData",
	"SatData",
	&asn_OP_SEQUENCE,
	asn_DEF_SatData_tags_1,
	sizeof(asn_DEF_SatData_tags_1)
		/sizeof(asn_DEF_SatData_tags_1[0]), /* 1 */
	asn_DEF_SatData_tags_1,	/* Same as above */
	sizeof(asn_DEF_SatData_tags_1)
		/sizeof(asn_DEF_SatData_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SatData_1,
	2,	/* Elements count */
	&asn_SPC_SatData_specs_1	/* Additional specs */
};

