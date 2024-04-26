/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-PowerClassExt.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_UE_PowerClassExt_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_UE_PowerClassExt_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_UE_PowerClassExt_value2enum_1[] = {
	{ 0,	6,	"class1" },
	{ 1,	6,	"class2" },
	{ 2,	6,	"class3" },
	{ 3,	6,	"class4" },
	{ 4,	6,	"spare4" },
	{ 5,	6,	"spare3" },
	{ 6,	6,	"spare2" },
	{ 7,	6,	"spare1" }
};
static const unsigned int asn_MAP_UE_PowerClassExt_enum2value_1[] = {
	0,	/* class1(0) */
	1,	/* class2(1) */
	2,	/* class3(2) */
	3,	/* class4(3) */
	7,	/* spare1(7) */
	6,	/* spare2(6) */
	5,	/* spare3(5) */
	4	/* spare4(4) */
};
const asn_INTEGER_specifics_t asn_SPC_UE_PowerClassExt_specs_1 = {
	asn_MAP_UE_PowerClassExt_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_UE_PowerClassExt_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_UE_PowerClassExt_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_UE_PowerClassExt = {
	"UE-PowerClassExt",
	"UE-PowerClassExt",
	&asn_OP_NativeEnumerated,
	asn_DEF_UE_PowerClassExt_tags_1,
	sizeof(asn_DEF_UE_PowerClassExt_tags_1)
		/sizeof(asn_DEF_UE_PowerClassExt_tags_1[0]), /* 1 */
	asn_DEF_UE_PowerClassExt_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_PowerClassExt_tags_1)
		/sizeof(asn_DEF_UE_PowerClassExt_tags_1[0]), /* 1 */
	{ &asn_OER_type_UE_PowerClassExt_constr_1, &asn_PER_type_UE_PowerClassExt_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_UE_PowerClassExt_specs_1	/* Additional specs */
};

