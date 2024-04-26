/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "T-304.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_T_304_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_T_304_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_T_304_value2enum_1[] = {
	{ 0,	5,	"ms100" },
	{ 1,	5,	"ms200" },
	{ 2,	5,	"ms400" },
	{ 3,	6,	"ms1000" },
	{ 4,	6,	"ms2000" },
	{ 5,	6,	"spare3" },
	{ 6,	6,	"spare2" },
	{ 7,	6,	"spare1" }
};
static const unsigned int asn_MAP_T_304_enum2value_1[] = {
	0,	/* ms100(0) */
	3,	/* ms1000(3) */
	1,	/* ms200(1) */
	4,	/* ms2000(4) */
	2,	/* ms400(2) */
	7,	/* spare1(7) */
	6,	/* spare2(6) */
	5	/* spare3(5) */
};
const asn_INTEGER_specifics_t asn_SPC_T_304_specs_1 = {
	asn_MAP_T_304_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_T_304_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_T_304_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_T_304 = {
	"T-304",
	"T-304",
	&asn_OP_NativeEnumerated,
	asn_DEF_T_304_tags_1,
	sizeof(asn_DEF_T_304_tags_1)
		/sizeof(asn_DEF_T_304_tags_1[0]), /* 1 */
	asn_DEF_T_304_tags_1,	/* Same as above */
	sizeof(asn_DEF_T_304_tags_1)
		/sizeof(asn_DEF_T_304_tags_1[0]), /* 1 */
	{ &asn_OER_type_T_304_constr_1, &asn_PER_type_T_304_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_T_304_specs_1	/* Additional specs */
};
