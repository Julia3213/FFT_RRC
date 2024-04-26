/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UTRAN-GPS-DriftRate.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_UTRAN_GPS_DriftRate_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_UTRAN_GPS_DriftRate_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  14 }	/* (0..14) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_UTRAN_GPS_DriftRate_value2enum_1[] = {
	{ 0,	15,	"utran-GPSDrift0" },
	{ 1,	15,	"utran-GPSDrift1" },
	{ 2,	15,	"utran-GPSDrift2" },
	{ 3,	15,	"utran-GPSDrift5" },
	{ 4,	16,	"utran-GPSDrift10" },
	{ 5,	16,	"utran-GPSDrift15" },
	{ 6,	16,	"utran-GPSDrift25" },
	{ 7,	16,	"utran-GPSDrift50" },
	{ 8,	16,	"utran-GPSDrift-1" },
	{ 9,	16,	"utran-GPSDrift-2" },
	{ 10,	16,	"utran-GPSDrift-5" },
	{ 11,	17,	"utran-GPSDrift-10" },
	{ 12,	17,	"utran-GPSDrift-15" },
	{ 13,	17,	"utran-GPSDrift-25" },
	{ 14,	17,	"utran-GPSDrift-50" }
};
static const unsigned int asn_MAP_UTRAN_GPS_DriftRate_enum2value_1[] = {
	8,	/* utran-GPSDrift-1(8) */
	11,	/* utran-GPSDrift-10(11) */
	12,	/* utran-GPSDrift-15(12) */
	9,	/* utran-GPSDrift-2(9) */
	13,	/* utran-GPSDrift-25(13) */
	10,	/* utran-GPSDrift-5(10) */
	14,	/* utran-GPSDrift-50(14) */
	0,	/* utran-GPSDrift0(0) */
	1,	/* utran-GPSDrift1(1) */
	4,	/* utran-GPSDrift10(4) */
	5,	/* utran-GPSDrift15(5) */
	2,	/* utran-GPSDrift2(2) */
	6,	/* utran-GPSDrift25(6) */
	3,	/* utran-GPSDrift5(3) */
	7	/* utran-GPSDrift50(7) */
};
const asn_INTEGER_specifics_t asn_SPC_UTRAN_GPS_DriftRate_specs_1 = {
	asn_MAP_UTRAN_GPS_DriftRate_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_UTRAN_GPS_DriftRate_enum2value_1,	/* N => "tag"; sorted by N */
	15,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_UTRAN_GPS_DriftRate_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_UTRAN_GPS_DriftRate = {
	"UTRAN-GPS-DriftRate",
	"UTRAN-GPS-DriftRate",
	&asn_OP_NativeEnumerated,
	asn_DEF_UTRAN_GPS_DriftRate_tags_1,
	sizeof(asn_DEF_UTRAN_GPS_DriftRate_tags_1)
		/sizeof(asn_DEF_UTRAN_GPS_DriftRate_tags_1[0]), /* 1 */
	asn_DEF_UTRAN_GPS_DriftRate_tags_1,	/* Same as above */
	sizeof(asn_DEF_UTRAN_GPS_DriftRate_tags_1)
		/sizeof(asn_DEF_UTRAN_GPS_DriftRate_tags_1[0]), /* 1 */
	{ &asn_OER_type_UTRAN_GPS_DriftRate_constr_1, &asn_PER_type_UTRAN_GPS_DriftRate_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_UTRAN_GPS_DriftRate_specs_1	/* Additional specs */
};
