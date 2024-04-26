/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TimerDiscard.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_TimerDiscard_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_TimerDiscard_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_TimerDiscard_value2enum_1[] = {
	{ 0,	5,	"td0-1" },
	{ 1,	6,	"td0-25" },
	{ 2,	5,	"td0-5" },
	{ 3,	6,	"td0-75" },
	{ 4,	3,	"td1" },
	{ 5,	6,	"td1-25" },
	{ 6,	5,	"td1-5" },
	{ 7,	6,	"td1-75" },
	{ 8,	3,	"td2" },
	{ 9,	5,	"td2-5" },
	{ 10,	3,	"td3" },
	{ 11,	5,	"td3-5" },
	{ 12,	3,	"td4" },
	{ 13,	5,	"td4-5" },
	{ 14,	3,	"td5" },
	{ 15,	5,	"td7-5" }
};
static const unsigned int asn_MAP_TimerDiscard_enum2value_1[] = {
	0,	/* td0-1(0) */
	1,	/* td0-25(1) */
	2,	/* td0-5(2) */
	3,	/* td0-75(3) */
	4,	/* td1(4) */
	5,	/* td1-25(5) */
	6,	/* td1-5(6) */
	7,	/* td1-75(7) */
	8,	/* td2(8) */
	9,	/* td2-5(9) */
	10,	/* td3(10) */
	11,	/* td3-5(11) */
	12,	/* td4(12) */
	13,	/* td4-5(13) */
	14,	/* td5(14) */
	15	/* td7-5(15) */
};
const asn_INTEGER_specifics_t asn_SPC_TimerDiscard_specs_1 = {
	asn_MAP_TimerDiscard_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TimerDiscard_enum2value_1,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_TimerDiscard_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TimerDiscard = {
	"TimerDiscard",
	"TimerDiscard",
	&asn_OP_NativeEnumerated,
	asn_DEF_TimerDiscard_tags_1,
	sizeof(asn_DEF_TimerDiscard_tags_1)
		/sizeof(asn_DEF_TimerDiscard_tags_1[0]), /* 1 */
	asn_DEF_TimerDiscard_tags_1,	/* Same as above */
	sizeof(asn_DEF_TimerDiscard_tags_1)
		/sizeof(asn_DEF_TimerDiscard_tags_1[0]), /* 1 */
	{ &asn_OER_type_TimerDiscard_constr_1, &asn_PER_type_TimerDiscard_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TimerDiscard_specs_1	/* Additional specs */
};

