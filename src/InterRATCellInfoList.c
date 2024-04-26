/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "InterRATCellInfoList.h"

#include "CellsForInterRATMeasList.h"
asn_TYPE_member_t asn_MBR_InterRATCellInfoList_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATCellInfoList, removedInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RemovedInterRATCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"removedInterRATCellList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATCellInfoList, newInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NewInterRATCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"newInterRATCellList"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATCellInfoList, cellsForInterRATMeasList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellsForInterRATMeasList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellsForInterRATMeasList"
		},
};
static const int asn_MAP_InterRATCellInfoList_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_InterRATCellInfoList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterRATCellInfoList_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* removedInterRATCellList */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* newInterRATCellList */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* cellsForInterRATMeasList */
};
asn_SEQUENCE_specifics_t asn_SPC_InterRATCellInfoList_specs_1 = {
	sizeof(struct InterRATCellInfoList),
	offsetof(struct InterRATCellInfoList, _asn_ctx),
	asn_MAP_InterRATCellInfoList_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_InterRATCellInfoList_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterRATCellInfoList = {
	"InterRATCellInfoList",
	"InterRATCellInfoList",
	&asn_OP_SEQUENCE,
	asn_DEF_InterRATCellInfoList_tags_1,
	sizeof(asn_DEF_InterRATCellInfoList_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_tags_1[0]), /* 1 */
	asn_DEF_InterRATCellInfoList_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATCellInfoList_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InterRATCellInfoList_1,
	3,	/* Elements count */
	&asn_SPC_InterRATCellInfoList_specs_1	/* Additional specs */
};

