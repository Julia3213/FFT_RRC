/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TimerStatusProhibit.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_TimerStatusProhibit_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_TimerStatusProhibit_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  0,  63 }	/* (0..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_TimerStatusProhibit_value2enum_1[] = {
	{ 0,	5,	"tsp10" },
	{ 1,	5,	"tsp20" },
	{ 2,	5,	"tsp30" },
	{ 3,	5,	"tsp40" },
	{ 4,	5,	"tsp50" },
	{ 5,	5,	"tsp60" },
	{ 6,	5,	"tsp70" },
	{ 7,	5,	"tsp80" },
	{ 8,	5,	"tsp90" },
	{ 9,	6,	"tsp100" },
	{ 10,	6,	"tsp110" },
	{ 11,	6,	"tsp120" },
	{ 12,	6,	"tsp130" },
	{ 13,	6,	"tsp140" },
	{ 14,	6,	"tsp150" },
	{ 15,	6,	"tsp160" },
	{ 16,	6,	"tsp170" },
	{ 17,	6,	"tsp180" },
	{ 18,	6,	"tsp190" },
	{ 19,	6,	"tsp200" },
	{ 20,	6,	"tsp210" },
	{ 21,	6,	"tsp220" },
	{ 22,	6,	"tsp230" },
	{ 23,	6,	"tsp240" },
	{ 24,	6,	"tsp250" },
	{ 25,	6,	"tsp260" },
	{ 26,	6,	"tsp270" },
	{ 27,	6,	"tsp280" },
	{ 28,	6,	"tsp290" },
	{ 29,	6,	"tsp300" },
	{ 30,	6,	"tsp310" },
	{ 31,	6,	"tsp320" },
	{ 32,	6,	"tsp330" },
	{ 33,	6,	"tsp340" },
	{ 34,	6,	"tsp350" },
	{ 35,	6,	"tsp360" },
	{ 36,	6,	"tsp370" },
	{ 37,	6,	"tsp380" },
	{ 38,	6,	"tsp390" },
	{ 39,	6,	"tsp400" },
	{ 40,	6,	"tsp410" },
	{ 41,	6,	"tsp420" },
	{ 42,	6,	"tsp430" },
	{ 43,	6,	"tsp440" },
	{ 44,	6,	"tsp450" },
	{ 45,	6,	"tsp460" },
	{ 46,	6,	"tsp470" },
	{ 47,	6,	"tsp480" },
	{ 48,	6,	"tsp490" },
	{ 49,	6,	"tsp500" },
	{ 50,	6,	"tsp510" },
	{ 51,	6,	"tsp520" },
	{ 52,	6,	"tsp530" },
	{ 53,	6,	"tsp540" },
	{ 54,	6,	"tsp550" },
	{ 55,	6,	"tsp600" },
	{ 56,	6,	"tsp650" },
	{ 57,	6,	"tsp700" },
	{ 58,	6,	"tsp750" },
	{ 59,	6,	"tsp800" },
	{ 60,	6,	"tsp850" },
	{ 61,	6,	"tsp900" },
	{ 62,	6,	"tsp950" },
	{ 63,	7,	"tsp1000" }
};
static const unsigned int asn_MAP_TimerStatusProhibit_enum2value_1[] = {
	0,	/* tsp10(0) */
	9,	/* tsp100(9) */
	63,	/* tsp1000(63) */
	10,	/* tsp110(10) */
	11,	/* tsp120(11) */
	12,	/* tsp130(12) */
	13,	/* tsp140(13) */
	14,	/* tsp150(14) */
	15,	/* tsp160(15) */
	16,	/* tsp170(16) */
	17,	/* tsp180(17) */
	18,	/* tsp190(18) */
	1,	/* tsp20(1) */
	19,	/* tsp200(19) */
	20,	/* tsp210(20) */
	21,	/* tsp220(21) */
	22,	/* tsp230(22) */
	23,	/* tsp240(23) */
	24,	/* tsp250(24) */
	25,	/* tsp260(25) */
	26,	/* tsp270(26) */
	27,	/* tsp280(27) */
	28,	/* tsp290(28) */
	2,	/* tsp30(2) */
	29,	/* tsp300(29) */
	30,	/* tsp310(30) */
	31,	/* tsp320(31) */
	32,	/* tsp330(32) */
	33,	/* tsp340(33) */
	34,	/* tsp350(34) */
	35,	/* tsp360(35) */
	36,	/* tsp370(36) */
	37,	/* tsp380(37) */
	38,	/* tsp390(38) */
	3,	/* tsp40(3) */
	39,	/* tsp400(39) */
	40,	/* tsp410(40) */
	41,	/* tsp420(41) */
	42,	/* tsp430(42) */
	43,	/* tsp440(43) */
	44,	/* tsp450(44) */
	45,	/* tsp460(45) */
	46,	/* tsp470(46) */
	47,	/* tsp480(47) */
	48,	/* tsp490(48) */
	4,	/* tsp50(4) */
	49,	/* tsp500(49) */
	50,	/* tsp510(50) */
	51,	/* tsp520(51) */
	52,	/* tsp530(52) */
	53,	/* tsp540(53) */
	54,	/* tsp550(54) */
	5,	/* tsp60(5) */
	55,	/* tsp600(55) */
	56,	/* tsp650(56) */
	6,	/* tsp70(6) */
	57,	/* tsp700(57) */
	58,	/* tsp750(58) */
	7,	/* tsp80(7) */
	59,	/* tsp800(59) */
	60,	/* tsp850(60) */
	8,	/* tsp90(8) */
	61,	/* tsp900(61) */
	62	/* tsp950(62) */
};
const asn_INTEGER_specifics_t asn_SPC_TimerStatusProhibit_specs_1 = {
	asn_MAP_TimerStatusProhibit_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TimerStatusProhibit_enum2value_1,	/* N => "tag"; sorted by N */
	64,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_TimerStatusProhibit_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TimerStatusProhibit = {
	"TimerStatusProhibit",
	"TimerStatusProhibit",
	&asn_OP_NativeEnumerated,
	asn_DEF_TimerStatusProhibit_tags_1,
	sizeof(asn_DEF_TimerStatusProhibit_tags_1)
		/sizeof(asn_DEF_TimerStatusProhibit_tags_1[0]), /* 1 */
	asn_DEF_TimerStatusProhibit_tags_1,	/* Same as above */
	sizeof(asn_DEF_TimerStatusProhibit_tags_1)
		/sizeof(asn_DEF_TimerStatusProhibit_tags_1[0]), /* 1 */
	{ &asn_OER_type_TimerStatusProhibit_constr_1, &asn_PER_type_TimerStatusProhibit_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TimerStatusProhibit_specs_1	/* Additional specs */
};
