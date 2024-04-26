/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "InterRATCellInfoList-r6.h"

#include "NewInterRATCellList.h"
#include "CellsForInterRATMeasList.h"
asn_TYPE_member_t asn_MBR_InterRATCellInfoList_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATCellInfoList_r6, removedInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RemovedInterRATCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"removedInterRATCellList"
		},
	{ ATF_POINTER, 3, offsetof(struct InterRATCellInfoList_r6, newInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NewInterRATCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"newInterRATCellList"
		},
	{ ATF_POINTER, 2, offsetof(struct InterRATCellInfoList_r6, cellsForInterRATMeasList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellsForInterRATMeasList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellsForInterRATMeasList"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATCellInfoList_r6, interRATCellInfoIndication_r6),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellInfoIndication,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interRATCellInfoIndication-r6"
		},
};
static const int asn_MAP_InterRATCellInfoList_r6_oms_1[] = { 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_InterRATCellInfoList_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterRATCellInfoList_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* removedInterRATCellList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* newInterRATCellList */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cellsForInterRATMeasList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* interRATCellInfoIndication-r6 */
};
asn_SEQUENCE_specifics_t asn_SPC_InterRATCellInfoList_r6_specs_1 = {
	sizeof(struct InterRATCellInfoList_r6),
	offsetof(struct InterRATCellInfoList_r6, _asn_ctx),
	asn_MAP_InterRATCellInfoList_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_InterRATCellInfoList_r6_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterRATCellInfoList_r6 = {
	"InterRATCellInfoList-r6",
	"InterRATCellInfoList-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_InterRATCellInfoList_r6_tags_1,
	sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1[0]), /* 1 */
	asn_DEF_InterRATCellInfoList_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InterRATCellInfoList_r6_1,
	4,	/* Elements count */
	&asn_SPC_InterRATCellInfoList_r6_specs_1	/* Additional specs */
};

