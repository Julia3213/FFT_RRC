/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DopplerUncertainty.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_DopplerUncertainty_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_DopplerUncertainty_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_DopplerUncertainty_value2enum_1[] = {
	{ 0,	6,	"hz12-5" },
	{ 1,	4,	"hz25" },
	{ 2,	4,	"hz50" },
	{ 3,	5,	"hz100" },
	{ 4,	5,	"hz200" },
	{ 5,	6,	"spare3" },
	{ 6,	6,	"spare2" },
	{ 7,	6,	"spare1" }
};
static const unsigned int asn_MAP_DopplerUncertainty_enum2value_1[] = {
	3,	/* hz100(3) */
	0,	/* hz12-5(0) */
	4,	/* hz200(4) */
	1,	/* hz25(1) */
	2,	/* hz50(2) */
	7,	/* spare1(7) */
	6,	/* spare2(6) */
	5	/* spare3(5) */
};
const asn_INTEGER_specifics_t asn_SPC_DopplerUncertainty_specs_1 = {
	asn_MAP_DopplerUncertainty_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_DopplerUncertainty_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_DopplerUncertainty_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_DopplerUncertainty = {
	"DopplerUncertainty",
	"DopplerUncertainty",
	&asn_OP_NativeEnumerated,
	asn_DEF_DopplerUncertainty_tags_1,
	sizeof(asn_DEF_DopplerUncertainty_tags_1)
		/sizeof(asn_DEF_DopplerUncertainty_tags_1[0]), /* 1 */
	asn_DEF_DopplerUncertainty_tags_1,	/* Same as above */
	sizeof(asn_DEF_DopplerUncertainty_tags_1)
		/sizeof(asn_DEF_DopplerUncertainty_tags_1[0]), /* 1 */
	{ &asn_OER_type_DopplerUncertainty_constr_1, &asn_PER_type_DopplerUncertainty_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_DopplerUncertainty_specs_1	/* Additional specs */
};

