/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CompressedModeMeasCapabTDD.h"

asn_TYPE_member_t asn_MBR_CompressedModeMeasCapabTDD_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CompressedModeMeasCapabTDD, radioFrequencyBandTDD),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RadioFrequencyBandTDD,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioFrequencyBandTDD"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CompressedModeMeasCapabTDD, dl_MeasurementsTDD),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-MeasurementsTDD"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CompressedModeMeasCapabTDD, ul_MeasurementsTDD),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-MeasurementsTDD"
		},
};
static const ber_tlv_tag_t asn_DEF_CompressedModeMeasCapabTDD_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CompressedModeMeasCapabTDD_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* radioFrequencyBandTDD */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-MeasurementsTDD */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ul-MeasurementsTDD */
};
asn_SEQUENCE_specifics_t asn_SPC_CompressedModeMeasCapabTDD_specs_1 = {
	sizeof(struct CompressedModeMeasCapabTDD),
	offsetof(struct CompressedModeMeasCapabTDD, _asn_ctx),
	asn_MAP_CompressedModeMeasCapabTDD_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CompressedModeMeasCapabTDD = {
	"CompressedModeMeasCapabTDD",
	"CompressedModeMeasCapabTDD",
	&asn_OP_SEQUENCE,
	asn_DEF_CompressedModeMeasCapabTDD_tags_1,
	sizeof(asn_DEF_CompressedModeMeasCapabTDD_tags_1)
		/sizeof(asn_DEF_CompressedModeMeasCapabTDD_tags_1[0]), /* 1 */
	asn_DEF_CompressedModeMeasCapabTDD_tags_1,	/* Same as above */
	sizeof(asn_DEF_CompressedModeMeasCapabTDD_tags_1)
		/sizeof(asn_DEF_CompressedModeMeasCapabTDD_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CompressedModeMeasCapabTDD_1,
	3,	/* Elements count */
	&asn_SPC_CompressedModeMeasCapabTDD_specs_1	/* Additional specs */
};

