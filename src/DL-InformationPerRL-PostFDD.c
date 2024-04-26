/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-InformationPerRL-PostFDD.h"

asn_TYPE_member_t asn_MBR_DL_InformationPerRL_PostFDD_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_PostFDD, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"primaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_InformationPerRL_PostFDD, dl_DPCH_InfoPerRL),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_DPCH_InfoPerRL_PostFDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-DPCH-InfoPerRL"
		},
};
static const ber_tlv_tag_t asn_DEF_DL_InformationPerRL_PostFDD_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_InformationPerRL_PostFDD_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-DPCH-InfoPerRL */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_InformationPerRL_PostFDD_specs_1 = {
	sizeof(struct DL_InformationPerRL_PostFDD),
	offsetof(struct DL_InformationPerRL_PostFDD, _asn_ctx),
	asn_MAP_DL_InformationPerRL_PostFDD_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_InformationPerRL_PostFDD = {
	"DL-InformationPerRL-PostFDD",
	"DL-InformationPerRL-PostFDD",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_InformationPerRL_PostFDD_tags_1,
	sizeof(asn_DEF_DL_InformationPerRL_PostFDD_tags_1)
		/sizeof(asn_DEF_DL_InformationPerRL_PostFDD_tags_1[0]), /* 1 */
	asn_DEF_DL_InformationPerRL_PostFDD_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_InformationPerRL_PostFDD_tags_1)
		/sizeof(asn_DEF_DL_InformationPerRL_PostFDD_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_InformationPerRL_PostFDD_1,
	2,	/* Elements count */
	&asn_SPC_DL_InformationPerRL_PostFDD_specs_1	/* Additional specs */
};
