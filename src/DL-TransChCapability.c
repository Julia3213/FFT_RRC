/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-TransChCapability.h"

asn_TYPE_member_t asn_MBR_DL_TransChCapability_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxNoBitsReceived),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNoBits,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxNoBitsReceived"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxConvCodeBitsReceived),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNoBits,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxConvCodeBitsReceived"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, turboDecodingSupport),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TurboSupport,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"turboDecodingSupport"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxSimultaneousTransChs),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxSimultaneousTransChsDL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxSimultaneousTransChs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxSimultaneousCCTrCH_Count),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxSimultaneousCCTrCH_Count,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxSimultaneousCCTrCH-Count"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxReceivedTransportBlocks),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxTransportBlocksDL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxReceivedTransportBlocks"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxNumberOfTFC),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNumberOfTFC_DL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxNumberOfTFC"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TransChCapability, maxNumberOfTF),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNumberOfTF,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxNumberOfTF"
		},
};
static const ber_tlv_tag_t asn_DEF_DL_TransChCapability_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_TransChCapability_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxNoBitsReceived */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* maxConvCodeBitsReceived */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* turboDecodingSupport */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* maxSimultaneousTransChs */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* maxSimultaneousCCTrCH-Count */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* maxReceivedTransportBlocks */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* maxNumberOfTFC */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* maxNumberOfTF */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_TransChCapability_specs_1 = {
	sizeof(struct DL_TransChCapability),
	offsetof(struct DL_TransChCapability, _asn_ctx),
	asn_MAP_DL_TransChCapability_tag2el_1,
	8,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_TransChCapability = {
	"DL-TransChCapability",
	"DL-TransChCapability",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_TransChCapability_tags_1,
	sizeof(asn_DEF_DL_TransChCapability_tags_1)
		/sizeof(asn_DEF_DL_TransChCapability_tags_1[0]), /* 1 */
	asn_DEF_DL_TransChCapability_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_TransChCapability_tags_1)
		/sizeof(asn_DEF_DL_TransChCapability_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_TransChCapability_1,
	8,	/* Elements count */
	&asn_SPC_DL_TransChCapability_specs_1	/* Additional specs */
};
