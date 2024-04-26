/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "BackoffControlParams.h"

asn_TYPE_member_t asn_MBR_BackoffControlParams_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, n_AP_RetransMax),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_N_AP_RetransMax,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"n-AP-RetransMax"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, n_AccessFails),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_N_AccessFails,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"n-AccessFails"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, nf_BO_NoAICH),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NF_BO_NoAICH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nf-BO-NoAICH"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, ns_BO_Busy),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NS_BO_Busy,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ns-BO-Busy"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, nf_BO_AllBusy),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NF_BO_AllBusy,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nf-BO-AllBusy"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, nf_BO_Mismatch),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NF_BO_Mismatch,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nf-BO-Mismatch"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BackoffControlParams, t_CPCH),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_T_CPCH,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t-CPCH"
		},
};
static const ber_tlv_tag_t asn_DEF_BackoffControlParams_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BackoffControlParams_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* n-AP-RetransMax */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* n-AccessFails */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* nf-BO-NoAICH */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* ns-BO-Busy */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* nf-BO-AllBusy */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* nf-BO-Mismatch */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* t-CPCH */
};
asn_SEQUENCE_specifics_t asn_SPC_BackoffControlParams_specs_1 = {
	sizeof(struct BackoffControlParams),
	offsetof(struct BackoffControlParams, _asn_ctx),
	asn_MAP_BackoffControlParams_tag2el_1,
	7,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_BackoffControlParams = {
	"BackoffControlParams",
	"BackoffControlParams",
	&asn_OP_SEQUENCE,
	asn_DEF_BackoffControlParams_tags_1,
	sizeof(asn_DEF_BackoffControlParams_tags_1)
		/sizeof(asn_DEF_BackoffControlParams_tags_1[0]), /* 1 */
	asn_DEF_BackoffControlParams_tags_1,	/* Same as above */
	sizeof(asn_DEF_BackoffControlParams_tags_1)
		/sizeof(asn_DEF_BackoffControlParams_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_BackoffControlParams_1,
	7,	/* Elements count */
	&asn_SPC_BackoffControlParams_specs_1	/* Additional specs */
};

