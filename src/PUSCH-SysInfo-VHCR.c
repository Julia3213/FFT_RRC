/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "PUSCH-SysInfo-VHCR.h"

#include "USCH-TransportChannelsInfo.h"
#include "TFCS.h"
asn_TYPE_member_t asn_MBR_PUSCH_SysInfo_VHCR_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PUSCH_SysInfo_VHCR, pusch_Identity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PUSCH_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-Identity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PUSCH_SysInfo_VHCR, pusch_Info_VHCR),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PUSCH_Info_VHCR,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-Info-VHCR"
		},
	{ ATF_POINTER, 2, offsetof(struct PUSCH_SysInfo_VHCR, usch_TransportChannelsInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_USCH_TransportChannelsInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"usch-TransportChannelsInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct PUSCH_SysInfo_VHCR, usch_TFCS),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TFCS,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"usch-TFCS"
		},
};
static const int asn_MAP_PUSCH_SysInfo_VHCR_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_PUSCH_SysInfo_VHCR_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PUSCH_SysInfo_VHCR_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pusch-Identity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pusch-Info-VHCR */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* usch-TransportChannelsInfo */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* usch-TFCS */
};
asn_SEQUENCE_specifics_t asn_SPC_PUSCH_SysInfo_VHCR_specs_1 = {
	sizeof(struct PUSCH_SysInfo_VHCR),
	offsetof(struct PUSCH_SysInfo_VHCR, _asn_ctx),
	asn_MAP_PUSCH_SysInfo_VHCR_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_PUSCH_SysInfo_VHCR_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PUSCH_SysInfo_VHCR = {
	"PUSCH-SysInfo-VHCR",
	"PUSCH-SysInfo-VHCR",
	&asn_OP_SEQUENCE,
	asn_DEF_PUSCH_SysInfo_VHCR_tags_1,
	sizeof(asn_DEF_PUSCH_SysInfo_VHCR_tags_1)
		/sizeof(asn_DEF_PUSCH_SysInfo_VHCR_tags_1[0]), /* 1 */
	asn_DEF_PUSCH_SysInfo_VHCR_tags_1,	/* Same as above */
	sizeof(asn_DEF_PUSCH_SysInfo_VHCR_tags_1)
		/sizeof(asn_DEF_PUSCH_SysInfo_VHCR_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PUSCH_SysInfo_VHCR_1,
	4,	/* Elements count */
	&asn_SPC_PUSCH_SysInfo_VHCR_specs_1	/* Additional specs */
};

