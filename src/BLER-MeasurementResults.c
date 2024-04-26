/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "BLER-MeasurementResults.h"

asn_TYPE_member_t asn_MBR_BLER_MeasurementResults_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct BLER_MeasurementResults, transportChannelIdentity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelIdentity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transportChannelIdentity"
		},
	{ ATF_POINTER, 1, offsetof(struct BLER_MeasurementResults, dl_TransportChannelBLER),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TransportChannelBLER,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-TransportChannelBLER"
		},
};
static const int asn_MAP_BLER_MeasurementResults_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_BLER_MeasurementResults_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BLER_MeasurementResults_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transportChannelIdentity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-TransportChannelBLER */
};
asn_SEQUENCE_specifics_t asn_SPC_BLER_MeasurementResults_specs_1 = {
	sizeof(struct BLER_MeasurementResults),
	offsetof(struct BLER_MeasurementResults, _asn_ctx),
	asn_MAP_BLER_MeasurementResults_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_BLER_MeasurementResults_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_BLER_MeasurementResults = {
	"BLER-MeasurementResults",
	"BLER-MeasurementResults",
	&asn_OP_SEQUENCE,
	asn_DEF_BLER_MeasurementResults_tags_1,
	sizeof(asn_DEF_BLER_MeasurementResults_tags_1)
		/sizeof(asn_DEF_BLER_MeasurementResults_tags_1[0]), /* 1 */
	asn_DEF_BLER_MeasurementResults_tags_1,	/* Same as above */
	sizeof(asn_DEF_BLER_MeasurementResults_tags_1)
		/sizeof(asn_DEF_BLER_MeasurementResults_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_BLER_MeasurementResults_1,
	2,	/* Elements count */
	&asn_SPC_BLER_MeasurementResults_specs_1	/* Additional specs */
};
