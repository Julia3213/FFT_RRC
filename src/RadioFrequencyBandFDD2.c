/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RadioFrequencyBandFDD2.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_RadioFrequencyBandFDD2_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RadioFrequencyBandFDD2_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_RadioFrequencyBandFDD2_value2enum_1[] = {
	{ 0,	8,	"bandVIII" },
	{ 1,	6,	"bandIX" },
	{ 2,	5,	"bandX" },
	{ 3,	6,	"bandXI" },
	{ 4,	7,	"bandXII" },
	{ 5,	8,	"bandXIII" },
	{ 6,	7,	"bandXIV" },
	{ 7,	6,	"bandXV" },
	{ 8,	7,	"bandXVI" },
	{ 9,	8,	"bandXVII" },
	{ 10,	9,	"bandXVIII" },
	{ 11,	7,	"bandXIX" },
	{ 12,	6,	"bandXX" },
	{ 13,	7,	"bandXXI" },
	{ 14,	8,	"bandXXII" },
	{ 15,	19,	"extension-indicator" }
};
static const unsigned int asn_MAP_RadioFrequencyBandFDD2_enum2value_1[] = {
	1,	/* bandIX(1) */
	0,	/* bandVIII(0) */
	2,	/* bandX(2) */
	3,	/* bandXI(3) */
	4,	/* bandXII(4) */
	5,	/* bandXIII(5) */
	6,	/* bandXIV(6) */
	11,	/* bandXIX(11) */
	7,	/* bandXV(7) */
	8,	/* bandXVI(8) */
	9,	/* bandXVII(9) */
	10,	/* bandXVIII(10) */
	12,	/* bandXX(12) */
	13,	/* bandXXI(13) */
	14,	/* bandXXII(14) */
	15	/* extension-indicator(15) */
};
const asn_INTEGER_specifics_t asn_SPC_RadioFrequencyBandFDD2_specs_1 = {
	asn_MAP_RadioFrequencyBandFDD2_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_RadioFrequencyBandFDD2_enum2value_1,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_RadioFrequencyBandFDD2_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RadioFrequencyBandFDD2 = {
	"RadioFrequencyBandFDD2",
	"RadioFrequencyBandFDD2",
	&asn_OP_NativeEnumerated,
	asn_DEF_RadioFrequencyBandFDD2_tags_1,
	sizeof(asn_DEF_RadioFrequencyBandFDD2_tags_1)
		/sizeof(asn_DEF_RadioFrequencyBandFDD2_tags_1[0]), /* 1 */
	asn_DEF_RadioFrequencyBandFDD2_tags_1,	/* Same as above */
	sizeof(asn_DEF_RadioFrequencyBandFDD2_tags_1)
		/sizeof(asn_DEF_RadioFrequencyBandFDD2_tags_1[0]), /* 1 */
	{ &asn_OER_type_RadioFrequencyBandFDD2_constr_1, &asn_PER_type_RadioFrequencyBandFDD2_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_RadioFrequencyBandFDD2_specs_1	/* Additional specs */
};
