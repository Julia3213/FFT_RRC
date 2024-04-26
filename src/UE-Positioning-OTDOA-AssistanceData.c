/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-Positioning-OTDOA-AssistanceData.h"

#include "UE-Positioning-OTDOA-ReferenceCellInfo.h"
#include "UE-Positioning-OTDOA-NeighbourCellList.h"
asn_TYPE_member_t asn_MBR_UE_Positioning_OTDOA_AssistanceData_1[] = {
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_OTDOA_AssistanceData, ue_positioning_OTDOA_ReferenceCellInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_OTDOA_ReferenceCellInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-positioning-OTDOA-ReferenceCellInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_OTDOA_AssistanceData, ue_positioning_OTDOA_NeighbourCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_OTDOA_NeighbourCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-positioning-OTDOA-NeighbourCellList"
		},
};
static const int asn_MAP_UE_Positioning_OTDOA_AssistanceData_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_Positioning_OTDOA_AssistanceData_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ue-positioning-OTDOA-ReferenceCellInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ue-positioning-OTDOA-NeighbourCellList */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_OTDOA_AssistanceData_specs_1 = {
	sizeof(struct UE_Positioning_OTDOA_AssistanceData),
	offsetof(struct UE_Positioning_OTDOA_AssistanceData, _asn_ctx),
	asn_MAP_UE_Positioning_OTDOA_AssistanceData_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UE_Positioning_OTDOA_AssistanceData_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_AssistanceData = {
	"UE-Positioning-OTDOA-AssistanceData",
	"UE-Positioning-OTDOA-AssistanceData",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1,
	sizeof(asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1)
		/sizeof(asn_DEF_UE_Positioning_OTDOA_AssistanceData_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_Positioning_OTDOA_AssistanceData_1,
	2,	/* Elements count */
	&asn_SPC_UE_Positioning_OTDOA_AssistanceData_specs_1	/* Additional specs */
};

