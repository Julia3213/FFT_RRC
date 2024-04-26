/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "MBMS-RequiredUEAction-Mod.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_oer_constraints_t asn_OER_type_MBMS_RequiredUEAction_Mod_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_MBMS_RequiredUEAction_Mod_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  5 }	/* (0..5) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_MBMS_RequiredUEAction_Mod_value2enum_1[] = {
	{ 0,	4,	"none" },
	{ 1,	19,	"acquireCountingInfo" },
	{ 2,	36,	"acquireCountingInfoPTM-RBsUnmodified" },
	{ 3,	17,	"acquirePTM-RBInfo" },
	{ 4,	12,	"requestPTPRB" },
	{ 5,	13,	"releasePTM-RB" }
};
static const unsigned int asn_MAP_MBMS_RequiredUEAction_Mod_enum2value_1[] = {
	1,	/* acquireCountingInfo(1) */
	2,	/* acquireCountingInfoPTM-RBsUnmodified(2) */
	3,	/* acquirePTM-RBInfo(3) */
	0,	/* none(0) */
	5,	/* releasePTM-RB(5) */
	4	/* requestPTPRB(4) */
};
const asn_INTEGER_specifics_t asn_SPC_MBMS_RequiredUEAction_Mod_specs_1 = {
	asn_MAP_MBMS_RequiredUEAction_Mod_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_MBMS_RequiredUEAction_Mod_enum2value_1,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_MBMS_RequiredUEAction_Mod_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_MBMS_RequiredUEAction_Mod = {
	"MBMS-RequiredUEAction-Mod",
	"MBMS-RequiredUEAction-Mod",
	&asn_OP_NativeEnumerated,
	asn_DEF_MBMS_RequiredUEAction_Mod_tags_1,
	sizeof(asn_DEF_MBMS_RequiredUEAction_Mod_tags_1)
		/sizeof(asn_DEF_MBMS_RequiredUEAction_Mod_tags_1[0]), /* 1 */
	asn_DEF_MBMS_RequiredUEAction_Mod_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBMS_RequiredUEAction_Mod_tags_1)
		/sizeof(asn_DEF_MBMS_RequiredUEAction_Mod_tags_1[0]), /* 1 */
	{ &asn_OER_type_MBMS_RequiredUEAction_Mod_constr_1, &asn_PER_type_MBMS_RequiredUEAction_Mod_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_MBMS_RequiredUEAction_Mod_specs_1	/* Additional specs */
};

