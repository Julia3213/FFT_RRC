/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RB-COUNT-C-MSB-InformationList.h"

#include "RB-COUNT-C-MSB-Information.h"
static asn_oer_constraints_t asn_OER_type_RB_COUNT_C_MSB_InformationList_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..27)) */};
asn_per_constraints_t asn_PER_type_RB_COUNT_C_MSB_InformationList_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 5,  5,  1,  27 }	/* (SIZE(1..27)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RB_COUNT_C_MSB_InformationList_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RB_COUNT_C_MSB_Information,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_RB_COUNT_C_MSB_InformationList_specs_1 = {
	sizeof(struct RB_COUNT_C_MSB_InformationList),
	offsetof(struct RB_COUNT_C_MSB_InformationList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_RB_COUNT_C_MSB_InformationList = {
	"RB-COUNT-C-MSB-InformationList",
	"RB-COUNT-C-MSB-InformationList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1,
	sizeof(asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1)
		/sizeof(asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1[0]), /* 1 */
	asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1,	/* Same as above */
	sizeof(asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1)
		/sizeof(asn_DEF_RB_COUNT_C_MSB_InformationList_tags_1[0]), /* 1 */
	{ &asn_OER_type_RB_COUNT_C_MSB_InformationList_constr_1, &asn_PER_type_RB_COUNT_C_MSB_InformationList_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_RB_COUNT_C_MSB_InformationList_1,
	1,	/* Single element */
	&asn_SPC_RB_COUNT_C_MSB_InformationList_specs_1	/* Additional specs */
};
