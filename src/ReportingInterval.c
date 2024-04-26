/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "ReportingInterval.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_ReportingInterval_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_ReportingInterval_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_ReportingInterval_value2enum_1[] = {
	{ 0,	21,	"noPeriodicalreporting" },
	{ 1,	6,	"ri0-25" },
	{ 2,	5,	"ri0-5" },
	{ 3,	3,	"ri1" },
	{ 4,	3,	"ri2" },
	{ 5,	3,	"ri4" },
	{ 6,	3,	"ri8" },
	{ 7,	4,	"ri16" }
};
static const unsigned int asn_MAP_ReportingInterval_enum2value_1[] = {
	0,	/* noPeriodicalreporting(0) */
	1,	/* ri0-25(1) */
	2,	/* ri0-5(2) */
	3,	/* ri1(3) */
	7,	/* ri16(7) */
	4,	/* ri2(4) */
	5,	/* ri4(5) */
	6	/* ri8(6) */
};
const asn_INTEGER_specifics_t asn_SPC_ReportingInterval_specs_1 = {
	asn_MAP_ReportingInterval_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_ReportingInterval_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ReportingInterval_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ReportingInterval = {
	"ReportingInterval",
	"ReportingInterval",
	&asn_OP_NativeEnumerated,
	asn_DEF_ReportingInterval_tags_1,
	sizeof(asn_DEF_ReportingInterval_tags_1)
		/sizeof(asn_DEF_ReportingInterval_tags_1[0]), /* 1 */
	asn_DEF_ReportingInterval_tags_1,	/* Same as above */
	sizeof(asn_DEF_ReportingInterval_tags_1)
		/sizeof(asn_DEF_ReportingInterval_tags_1[0]), /* 1 */
	{ &asn_OER_type_ReportingInterval_constr_1, &asn_PER_type_ReportingInterval_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ReportingInterval_specs_1	/* Additional specs */
};
