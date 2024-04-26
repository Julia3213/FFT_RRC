/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DomainSpecificAccessRestriction-v670ext.h"

#include "AccessClassBarredList.h"
static asn_oer_constraints_t asn_OER_type_DomainSpecificAccessRestriction_v670ext_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_DomainSpecificAccessRestriction_v670ext_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_restriction_3[] = {
	{ ATF_POINTER, 1, offsetof(struct DomainSpecificAccessRestriction_v670ext__restriction, domainSpecficAccessClassBarredList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccessClassBarredList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"domainSpecficAccessClassBarredList"
		},
};
static const int asn_MAP_restriction_oms_3[] = { 0 };
static const ber_tlv_tag_t asn_DEF_restriction_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_restriction_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* domainSpecficAccessClassBarredList */
};
static asn_SEQUENCE_specifics_t asn_SPC_restriction_specs_3 = {
	sizeof(struct DomainSpecificAccessRestriction_v670ext__restriction),
	offsetof(struct DomainSpecificAccessRestriction_v670ext__restriction, _asn_ctx),
	asn_MAP_restriction_tag2el_3,
	1,	/* Count of tags in the map */
	asn_MAP_restriction_oms_3,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_restriction_3 = {
	"restriction",
	"restriction",
	&asn_OP_SEQUENCE,
	asn_DEF_restriction_tags_3,
	sizeof(asn_DEF_restriction_tags_3)
		/sizeof(asn_DEF_restriction_tags_3[0]) - 1, /* 1 */
	asn_DEF_restriction_tags_3,	/* Same as above */
	sizeof(asn_DEF_restriction_tags_3)
		/sizeof(asn_DEF_restriction_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_restriction_3,
	1,	/* Elements count */
	&asn_SPC_restriction_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DomainSpecificAccessRestriction_v670ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DomainSpecificAccessRestriction_v670ext, choice.noRestriction),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"noRestriction"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DomainSpecificAccessRestriction_v670ext, choice.restriction),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_restriction_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"restriction"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_DomainSpecificAccessRestriction_v670ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* noRestriction */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* restriction */
};
asn_CHOICE_specifics_t asn_SPC_DomainSpecificAccessRestriction_v670ext_specs_1 = {
	sizeof(struct DomainSpecificAccessRestriction_v670ext),
	offsetof(struct DomainSpecificAccessRestriction_v670ext, _asn_ctx),
	offsetof(struct DomainSpecificAccessRestriction_v670ext, present),
	sizeof(((struct DomainSpecificAccessRestriction_v670ext *)0)->present),
	asn_MAP_DomainSpecificAccessRestriction_v670ext_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_DomainSpecificAccessRestriction_v670ext = {
	"DomainSpecificAccessRestriction-v670ext",
	"DomainSpecificAccessRestriction-v670ext",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_DomainSpecificAccessRestriction_v670ext_constr_1, &asn_PER_type_DomainSpecificAccessRestriction_v670ext_constr_1, CHOICE_constraint },
	asn_MBR_DomainSpecificAccessRestriction_v670ext_1,
	2,	/* Elements count */
	&asn_SPC_DomainSpecificAccessRestriction_v670ext_specs_1	/* Additional specs */
};

