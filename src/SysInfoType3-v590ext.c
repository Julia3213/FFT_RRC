/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SysInfoType3-v590ext.h"

#include "CellSelectReselectInfo-v590ext.h"
asn_TYPE_member_t asn_MBR_SysInfoType3_v590ext_1[] = {
	{ ATF_POINTER, 1, offsetof(struct SysInfoType3_v590ext, cellSelectReselectInfo_v590ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellSelectReselectInfo_v590ext,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellSelectReselectInfo-v590ext"
		},
};
static const int asn_MAP_SysInfoType3_v590ext_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_SysInfoType3_v590ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SysInfoType3_v590ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* cellSelectReselectInfo-v590ext */
};
asn_SEQUENCE_specifics_t asn_SPC_SysInfoType3_v590ext_specs_1 = {
	sizeof(struct SysInfoType3_v590ext),
	offsetof(struct SysInfoType3_v590ext, _asn_ctx),
	asn_MAP_SysInfoType3_v590ext_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_SysInfoType3_v590ext_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SysInfoType3_v590ext = {
	"SysInfoType3-v590ext",
	"SysInfoType3-v590ext",
	&asn_OP_SEQUENCE,
	asn_DEF_SysInfoType3_v590ext_tags_1,
	sizeof(asn_DEF_SysInfoType3_v590ext_tags_1)
		/sizeof(asn_DEF_SysInfoType3_v590ext_tags_1[0]), /* 1 */
	asn_DEF_SysInfoType3_v590ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_SysInfoType3_v590ext_tags_1)
		/sizeof(asn_DEF_SysInfoType3_v590ext_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SysInfoType3_v590ext_1,
	1,	/* Elements count */
	&asn_SPC_SysInfoType3_v590ext_specs_1	/* Additional specs */
};

