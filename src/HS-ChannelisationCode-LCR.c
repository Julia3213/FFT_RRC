/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "HS-ChannelisationCode-LCR.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_HS_ChannelisationCode_LCR_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_HS_ChannelisationCode_LCR_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_HS_ChannelisationCode_LCR_value2enum_1[] = {
	{ 0,	6,	"cc16-1" },
	{ 1,	6,	"cc16-2" },
	{ 2,	6,	"cc16-3" },
	{ 3,	6,	"cc16-4" },
	{ 4,	6,	"cc16-5" },
	{ 5,	6,	"cc16-6" },
	{ 6,	6,	"cc16-7" },
	{ 7,	6,	"cc16-8" },
	{ 8,	6,	"cc16-9" },
	{ 9,	7,	"cc16-10" },
	{ 10,	7,	"cc16-11" },
	{ 11,	7,	"cc16-12" },
	{ 12,	7,	"cc16-13" },
	{ 13,	7,	"cc16-14" },
	{ 14,	7,	"cc16-15" },
	{ 15,	7,	"cc16-16" }
};
static const unsigned int asn_MAP_HS_ChannelisationCode_LCR_enum2value_1[] = {
	0,	/* cc16-1(0) */
	9,	/* cc16-10(9) */
	10,	/* cc16-11(10) */
	11,	/* cc16-12(11) */
	12,	/* cc16-13(12) */
	13,	/* cc16-14(13) */
	14,	/* cc16-15(14) */
	15,	/* cc16-16(15) */
	1,	/* cc16-2(1) */
	2,	/* cc16-3(2) */
	3,	/* cc16-4(3) */
	4,	/* cc16-5(4) */
	5,	/* cc16-6(5) */
	6,	/* cc16-7(6) */
	7,	/* cc16-8(7) */
	8	/* cc16-9(8) */
};
const asn_INTEGER_specifics_t asn_SPC_HS_ChannelisationCode_LCR_specs_1 = {
	asn_MAP_HS_ChannelisationCode_LCR_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_HS_ChannelisationCode_LCR_enum2value_1,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_HS_ChannelisationCode_LCR_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_HS_ChannelisationCode_LCR = {
	"HS-ChannelisationCode-LCR",
	"HS-ChannelisationCode-LCR",
	&asn_OP_NativeEnumerated,
	asn_DEF_HS_ChannelisationCode_LCR_tags_1,
	sizeof(asn_DEF_HS_ChannelisationCode_LCR_tags_1)
		/sizeof(asn_DEF_HS_ChannelisationCode_LCR_tags_1[0]), /* 1 */
	asn_DEF_HS_ChannelisationCode_LCR_tags_1,	/* Same as above */
	sizeof(asn_DEF_HS_ChannelisationCode_LCR_tags_1)
		/sizeof(asn_DEF_HS_ChannelisationCode_LCR_tags_1[0]), /* 1 */
	{ &asn_OER_type_HS_ChannelisationCode_LCR_constr_1, &asn_PER_type_HS_ChannelisationCode_LCR_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_HS_ChannelisationCode_LCR_specs_1	/* Additional specs */
};

