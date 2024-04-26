/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "E-DPDCH-MaxChannelisationCodes.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_E_DPDCH_MaxChannelisationCodes_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_E_DPDCH_MaxChannelisationCodes_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  9 }	/* (0..9) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_E_DPDCH_MaxChannelisationCodes_value2enum_1[] = {
	{ 0,	5,	"sf256" },
	{ 1,	5,	"sf128" },
	{ 2,	4,	"sf64" },
	{ 3,	4,	"sf32" },
	{ 4,	4,	"sf16" },
	{ 5,	3,	"sf8" },
	{ 6,	3,	"sf4" },
	{ 7,	5,	"sf4x2" },
	{ 8,	5,	"sf2x2" },
	{ 9,	15,	"sf4x2-and-sf2x2" }
};
static const unsigned int asn_MAP_E_DPDCH_MaxChannelisationCodes_enum2value_1[] = {
	1,	/* sf128(1) */
	4,	/* sf16(4) */
	0,	/* sf256(0) */
	8,	/* sf2x2(8) */
	3,	/* sf32(3) */
	6,	/* sf4(6) */
	7,	/* sf4x2(7) */
	9,	/* sf4x2-and-sf2x2(9) */
	2,	/* sf64(2) */
	5	/* sf8(5) */
};
const asn_INTEGER_specifics_t asn_SPC_E_DPDCH_MaxChannelisationCodes_specs_1 = {
	asn_MAP_E_DPDCH_MaxChannelisationCodes_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_E_DPDCH_MaxChannelisationCodes_enum2value_1,	/* N => "tag"; sorted by N */
	10,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_E_DPDCH_MaxChannelisationCodes = {
	"E-DPDCH-MaxChannelisationCodes",
	"E-DPDCH-MaxChannelisationCodes",
	&asn_OP_NativeEnumerated,
	asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1,
	sizeof(asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1)
		/sizeof(asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1[0]), /* 1 */
	asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1)
		/sizeof(asn_DEF_E_DPDCH_MaxChannelisationCodes_tags_1[0]), /* 1 */
	{ &asn_OER_type_E_DPDCH_MaxChannelisationCodes_constr_1, &asn_PER_type_E_DPDCH_MaxChannelisationCodes_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_E_DPDCH_MaxChannelisationCodes_specs_1	/* Additional specs */
};

