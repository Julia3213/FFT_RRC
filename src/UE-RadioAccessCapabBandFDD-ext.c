/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-RadioAccessCapabBandFDD-ext.h"

asn_TYPE_member_t asn_MBR_UE_RadioAccessCapabBandFDD_ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_RadioAccessCapabBandFDD_ext, radioFrequencyBandFDD),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RadioFrequencyBandFDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioFrequencyBandFDD"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_RadioAccessCapabBandFDD_ext, compressedModeMeasCapabFDDList_ext),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CompressedModeMeasCapabFDDList_ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"compressedModeMeasCapabFDDList-ext"
		},
};
static const ber_tlv_tag_t asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_RadioAccessCapabBandFDD_ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* radioFrequencyBandFDD */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* compressedModeMeasCapabFDDList-ext */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapabBandFDD_ext_specs_1 = {
	sizeof(struct UE_RadioAccessCapabBandFDD_ext),
	offsetof(struct UE_RadioAccessCapabBandFDD_ext, _asn_ctx),
	asn_MAP_UE_RadioAccessCapabBandFDD_ext_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapabBandFDD_ext = {
	"UE-RadioAccessCapabBandFDD-ext",
	"UE-RadioAccessCapabBandFDD-ext",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1,
	sizeof(asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1[0]), /* 1 */
	asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapabBandFDD_ext_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_RadioAccessCapabBandFDD_ext_1,
	2,	/* Elements count */
	&asn_SPC_UE_RadioAccessCapabBandFDD_ext_specs_1	/* Additional specs */
};
