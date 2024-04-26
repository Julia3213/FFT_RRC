/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MidambleConfigurationBurstType1and3.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_MidambleConfigurationBurstType1and3_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_MidambleConfigurationBurstType1and3_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_MidambleConfigurationBurstType1and3_value2enum_1[] = {
	{ 0,	3,	"ms4" },
	{ 1,	3,	"ms8" },
	{ 2,	4,	"ms16" }
};
static const unsigned int asn_MAP_MidambleConfigurationBurstType1and3_enum2value_1[] = {
	2,	/* ms16(2) */
	0,	/* ms4(0) */
	1	/* ms8(1) */
};
const asn_INTEGER_specifics_t asn_SPC_MidambleConfigurationBurstType1and3_specs_1 = {
	asn_MAP_MidambleConfigurationBurstType1and3_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_MidambleConfigurationBurstType1and3_enum2value_1,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_MidambleConfigurationBurstType1and3_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_MidambleConfigurationBurstType1and3 = {
	"MidambleConfigurationBurstType1and3",
	"MidambleConfigurationBurstType1and3",
	&asn_OP_NativeEnumerated,
	asn_DEF_MidambleConfigurationBurstType1and3_tags_1,
	sizeof(asn_DEF_MidambleConfigurationBurstType1and3_tags_1)
		/sizeof(asn_DEF_MidambleConfigurationBurstType1and3_tags_1[0]), /* 1 */
	asn_DEF_MidambleConfigurationBurstType1and3_tags_1,	/* Same as above */
	sizeof(asn_DEF_MidambleConfigurationBurstType1and3_tags_1)
		/sizeof(asn_DEF_MidambleConfigurationBurstType1and3_tags_1[0]), /* 1 */
	{ &asn_OER_type_MidambleConfigurationBurstType1and3_constr_1, &asn_PER_type_MidambleConfigurationBurstType1and3_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_MidambleConfigurationBurstType1and3_specs_1	/* Additional specs */
};

