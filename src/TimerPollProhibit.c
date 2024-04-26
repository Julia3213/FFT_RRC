/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TimerPollProhibit.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_TimerPollProhibit_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_TimerPollProhibit_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  0,  63 }	/* (0..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_TimerPollProhibit_value2enum_1[] = {
	{ 0,	5,	"tpp10" },
	{ 1,	5,	"tpp20" },
	{ 2,	5,	"tpp30" },
	{ 3,	5,	"tpp40" },
	{ 4,	5,	"tpp50" },
	{ 5,	5,	"tpp60" },
	{ 6,	5,	"tpp70" },
	{ 7,	5,	"tpp80" },
	{ 8,	5,	"tpp90" },
	{ 9,	6,	"tpp100" },
	{ 10,	6,	"tpp110" },
	{ 11,	6,	"tpp120" },
	{ 12,	6,	"tpp130" },
	{ 13,	6,	"tpp140" },
	{ 14,	6,	"tpp150" },
	{ 15,	6,	"tpp160" },
	{ 16,	6,	"tpp170" },
	{ 17,	6,	"tpp180" },
	{ 18,	6,	"tpp190" },
	{ 19,	6,	"tpp200" },
	{ 20,	6,	"tpp210" },
	{ 21,	6,	"tpp220" },
	{ 22,	6,	"tpp230" },
	{ 23,	6,	"tpp240" },
	{ 24,	6,	"tpp250" },
	{ 25,	6,	"tpp260" },
	{ 26,	6,	"tpp270" },
	{ 27,	6,	"tpp280" },
	{ 28,	6,	"tpp290" },
	{ 29,	6,	"tpp300" },
	{ 30,	6,	"tpp310" },
	{ 31,	6,	"tpp320" },
	{ 32,	6,	"tpp330" },
	{ 33,	6,	"tpp340" },
	{ 34,	6,	"tpp350" },
	{ 35,	6,	"tpp360" },
	{ 36,	6,	"tpp370" },
	{ 37,	6,	"tpp380" },
	{ 38,	6,	"tpp390" },
	{ 39,	6,	"tpp400" },
	{ 40,	6,	"tpp410" },
	{ 41,	6,	"tpp420" },
	{ 42,	6,	"tpp430" },
	{ 43,	6,	"tpp440" },
	{ 44,	6,	"tpp450" },
	{ 45,	6,	"tpp460" },
	{ 46,	6,	"tpp470" },
	{ 47,	6,	"tpp480" },
	{ 48,	6,	"tpp490" },
	{ 49,	6,	"tpp500" },
	{ 50,	6,	"tpp510" },
	{ 51,	6,	"tpp520" },
	{ 52,	6,	"tpp530" },
	{ 53,	6,	"tpp540" },
	{ 54,	6,	"tpp550" },
	{ 55,	6,	"tpp600" },
	{ 56,	6,	"tpp650" },
	{ 57,	6,	"tpp700" },
	{ 58,	6,	"tpp750" },
	{ 59,	6,	"tpp800" },
	{ 60,	6,	"tpp850" },
	{ 61,	6,	"tpp900" },
	{ 62,	6,	"tpp950" },
	{ 63,	7,	"tpp1000" }
};
static const unsigned int asn_MAP_TimerPollProhibit_enum2value_1[] = {
	0,	/* tpp10(0) */
	9,	/* tpp100(9) */
	63,	/* tpp1000(63) */
	10,	/* tpp110(10) */
	11,	/* tpp120(11) */
	12,	/* tpp130(12) */
	13,	/* tpp140(13) */
	14,	/* tpp150(14) */
	15,	/* tpp160(15) */
	16,	/* tpp170(16) */
	17,	/* tpp180(17) */
	18,	/* tpp190(18) */
	1,	/* tpp20(1) */
	19,	/* tpp200(19) */
	20,	/* tpp210(20) */
	21,	/* tpp220(21) */
	22,	/* tpp230(22) */
	23,	/* tpp240(23) */
	24,	/* tpp250(24) */
	25,	/* tpp260(25) */
	26,	/* tpp270(26) */
	27,	/* tpp280(27) */
	28,	/* tpp290(28) */
	2,	/* tpp30(2) */
	29,	/* tpp300(29) */
	30,	/* tpp310(30) */
	31,	/* tpp320(31) */
	32,	/* tpp330(32) */
	33,	/* tpp340(33) */
	34,	/* tpp350(34) */
	35,	/* tpp360(35) */
	36,	/* tpp370(36) */
	37,	/* tpp380(37) */
	38,	/* tpp390(38) */
	3,	/* tpp40(3) */
	39,	/* tpp400(39) */
	40,	/* tpp410(40) */
	41,	/* tpp420(41) */
	42,	/* tpp430(42) */
	43,	/* tpp440(43) */
	44,	/* tpp450(44) */
	45,	/* tpp460(45) */
	46,	/* tpp470(46) */
	47,	/* tpp480(47) */
	48,	/* tpp490(48) */
	4,	/* tpp50(4) */
	49,	/* tpp500(49) */
	50,	/* tpp510(50) */
	51,	/* tpp520(51) */
	52,	/* tpp530(52) */
	53,	/* tpp540(53) */
	54,	/* tpp550(54) */
	5,	/* tpp60(5) */
	55,	/* tpp600(55) */
	56,	/* tpp650(56) */
	6,	/* tpp70(6) */
	57,	/* tpp700(57) */
	58,	/* tpp750(58) */
	7,	/* tpp80(7) */
	59,	/* tpp800(59) */
	60,	/* tpp850(60) */
	8,	/* tpp90(8) */
	61,	/* tpp900(61) */
	62	/* tpp950(62) */
};
const asn_INTEGER_specifics_t asn_SPC_TimerPollProhibit_specs_1 = {
	asn_MAP_TimerPollProhibit_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TimerPollProhibit_enum2value_1,	/* N => "tag"; sorted by N */
	64,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_TimerPollProhibit_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TimerPollProhibit = {
	"TimerPollProhibit",
	"TimerPollProhibit",
	&asn_OP_NativeEnumerated,
	asn_DEF_TimerPollProhibit_tags_1,
	sizeof(asn_DEF_TimerPollProhibit_tags_1)
		/sizeof(asn_DEF_TimerPollProhibit_tags_1[0]), /* 1 */
	asn_DEF_TimerPollProhibit_tags_1,	/* Same as above */
	sizeof(asn_DEF_TimerPollProhibit_tags_1)
		/sizeof(asn_DEF_TimerPollProhibit_tags_1[0]), /* 1 */
	{ &asn_OER_type_TimerPollProhibit_constr_1, &asn_PER_type_TimerPollProhibit_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TimerPollProhibit_specs_1	/* Additional specs */
};

