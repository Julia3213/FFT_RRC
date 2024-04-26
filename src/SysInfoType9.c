/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SysInfoType9.h"

static const ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_3 = {
	sizeof(struct SysInfoType9__nonCriticalExtensions),
	offsetof(struct SysInfoType9__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_3 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
	&asn_OP_SEQUENCE,
	asn_DEF_nonCriticalExtensions_tags_3,
	sizeof(asn_DEF_nonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_3[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_3,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_3)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SysInfoType9_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SysInfoType9, dummy),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CPCH_PersistenceLevelsList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dummy"
		},
	{ ATF_POINTER, 1, offsetof(struct SysInfoType9, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtensions"
		},
};
static const int asn_MAP_SysInfoType9_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_SysInfoType9_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SysInfoType9_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dummy */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_SysInfoType9_specs_1 = {
	sizeof(struct SysInfoType9),
	offsetof(struct SysInfoType9, _asn_ctx),
	asn_MAP_SysInfoType9_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_SysInfoType9_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SysInfoType9 = {
	"SysInfoType9",
	"SysInfoType9",
	&asn_OP_SEQUENCE,
	asn_DEF_SysInfoType9_tags_1,
	sizeof(asn_DEF_SysInfoType9_tags_1)
		/sizeof(asn_DEF_SysInfoType9_tags_1[0]), /* 1 */
	asn_DEF_SysInfoType9_tags_1,	/* Same as above */
	sizeof(asn_DEF_SysInfoType9_tags_1)
		/sizeof(asn_DEF_SysInfoType9_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SysInfoType9_1,
	2,	/* Elements count */
	&asn_SPC_SysInfoType9_specs_1	/* Additional specs */
};

