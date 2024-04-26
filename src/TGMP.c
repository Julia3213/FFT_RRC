/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TGMP.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_TGMP_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_TGMP_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  5 }	/* (0..5) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_TGMP_value2enum_1[] = {
	{ 0,	15,	"tdd-Measurement" },
	{ 1,	15,	"fdd-Measurement" },
	{ 2,	26,	"gsm-CarrierRSSIMeasurement" },
	{ 3,	29,	"gsm-initialBSICIdentification" },
	{ 4,	21,	"gsmBSICReconfirmation" },
	{ 5,	13,	"multi-carrier" }
};
static const unsigned int asn_MAP_TGMP_enum2value_1[] = {
	1,	/* fdd-Measurement(1) */
	2,	/* gsm-CarrierRSSIMeasurement(2) */
	3,	/* gsm-initialBSICIdentification(3) */
	4,	/* gsmBSICReconfirmation(4) */
	5,	/* multi-carrier(5) */
	0	/* tdd-Measurement(0) */
};
const asn_INTEGER_specifics_t asn_SPC_TGMP_specs_1 = {
	asn_MAP_TGMP_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TGMP_enum2value_1,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_TGMP_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TGMP = {
	"TGMP",
	"TGMP",
	&asn_OP_NativeEnumerated,
	asn_DEF_TGMP_tags_1,
	sizeof(asn_DEF_TGMP_tags_1)
		/sizeof(asn_DEF_TGMP_tags_1[0]), /* 1 */
	asn_DEF_TGMP_tags_1,	/* Same as above */
	sizeof(asn_DEF_TGMP_tags_1)
		/sizeof(asn_DEF_TGMP_tags_1[0]), /* 1 */
	{ &asn_OER_type_TGMP_constr_1, &asn_PER_type_TGMP_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TGMP_specs_1	/* Additional specs */
};

