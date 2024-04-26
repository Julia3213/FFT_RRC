/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "ThresholdPositionChange.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_ThresholdPositionChange_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_ThresholdPositionChange_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_ThresholdPositionChange_value2enum_1[] = {
	{ 0,	4,	"pc10" },
	{ 1,	4,	"pc20" },
	{ 2,	4,	"pc30" },
	{ 3,	4,	"pc40" },
	{ 4,	4,	"pc50" },
	{ 5,	5,	"pc100" },
	{ 6,	5,	"pc200" },
	{ 7,	5,	"pc300" },
	{ 8,	5,	"pc500" },
	{ 9,	6,	"pc1000" },
	{ 10,	6,	"pc2000" },
	{ 11,	6,	"pc5000" },
	{ 12,	7,	"pc10000" },
	{ 13,	7,	"pc20000" },
	{ 14,	7,	"pc50000" },
	{ 15,	8,	"pc100000" }
};
static const unsigned int asn_MAP_ThresholdPositionChange_enum2value_1[] = {
	0,	/* pc10(0) */
	5,	/* pc100(5) */
	9,	/* pc1000(9) */
	12,	/* pc10000(12) */
	15,	/* pc100000(15) */
	1,	/* pc20(1) */
	6,	/* pc200(6) */
	10,	/* pc2000(10) */
	13,	/* pc20000(13) */
	2,	/* pc30(2) */
	7,	/* pc300(7) */
	3,	/* pc40(3) */
	4,	/* pc50(4) */
	8,	/* pc500(8) */
	11,	/* pc5000(11) */
	14	/* pc50000(14) */
};
const asn_INTEGER_specifics_t asn_SPC_ThresholdPositionChange_specs_1 = {
	asn_MAP_ThresholdPositionChange_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_ThresholdPositionChange_enum2value_1,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ThresholdPositionChange_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ThresholdPositionChange = {
	"ThresholdPositionChange",
	"ThresholdPositionChange",
	&asn_OP_NativeEnumerated,
	asn_DEF_ThresholdPositionChange_tags_1,
	sizeof(asn_DEF_ThresholdPositionChange_tags_1)
		/sizeof(asn_DEF_ThresholdPositionChange_tags_1[0]), /* 1 */
	asn_DEF_ThresholdPositionChange_tags_1,	/* Same as above */
	sizeof(asn_DEF_ThresholdPositionChange_tags_1)
		/sizeof(asn_DEF_ThresholdPositionChange_tags_1[0]), /* 1 */
	{ &asn_OER_type_ThresholdPositionChange_constr_1, &asn_PER_type_ThresholdPositionChange_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ThresholdPositionChange_specs_1	/* Additional specs */
};

