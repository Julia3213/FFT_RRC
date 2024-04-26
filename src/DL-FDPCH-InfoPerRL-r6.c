/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DL-FDPCH-InfoPerRL-r6.h"

#include "SecondaryCPICH-Info.h"
static int
memb_dl_ChannelisationCode_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 255)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_dl_ChannelisationCode_constr_6 CC_NOTUSED = {
	{ 1, 1 }	/* (0..255) */,
	-1};
static asn_per_constraints_t asn_PER_memb_dl_ChannelisationCode_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_DL_FDPCH_InfoPerRL_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_FDPCH_InfoPerRL_r6, pCPICH_UsageForChannelEst),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PCPICH_UsageForChannelEst,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pCPICH-UsageForChannelEst"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_FDPCH_InfoPerRL_r6, fdpch_FrameOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DPCH_FrameOffset,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fdpch-FrameOffset"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_FDPCH_InfoPerRL_r6, secondaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryCPICH_Info,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryCPICH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_FDPCH_InfoPerRL_r6, secondaryScramblingCode),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SecondaryScramblingCode,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"secondaryScramblingCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_FDPCH_InfoPerRL_r6, dl_ChannelisationCode),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_dl_ChannelisationCode_constr_6, &asn_PER_memb_dl_ChannelisationCode_constr_6,  memb_dl_ChannelisationCode_constraint_1 },
		0, 0, /* No default value */
		"dl-ChannelisationCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_FDPCH_InfoPerRL_r6, tpc_CombinationIndex),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TPC_CombinationIndex,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tpc-CombinationIndex"
		},
};
static const int asn_MAP_DL_FDPCH_InfoPerRL_r6_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DL_FDPCH_InfoPerRL_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pCPICH-UsageForChannelEst */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* fdpch-FrameOffset */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* secondaryCPICH-Info */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* secondaryScramblingCode */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* dl-ChannelisationCode */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* tpc-CombinationIndex */
};
asn_SEQUENCE_specifics_t asn_SPC_DL_FDPCH_InfoPerRL_r6_specs_1 = {
	sizeof(struct DL_FDPCH_InfoPerRL_r6),
	offsetof(struct DL_FDPCH_InfoPerRL_r6, _asn_ctx),
	asn_MAP_DL_FDPCH_InfoPerRL_r6_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_DL_FDPCH_InfoPerRL_r6_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DL_FDPCH_InfoPerRL_r6 = {
	"DL-FDPCH-InfoPerRL-r6",
	"DL-FDPCH-InfoPerRL-r6",
	&asn_OP_SEQUENCE,
	asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1,
	sizeof(asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1)
		/sizeof(asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1[0]), /* 1 */
	asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1)
		/sizeof(asn_DEF_DL_FDPCH_InfoPerRL_r6_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DL_FDPCH_InfoPerRL_r6_1,
	6,	/* Elements count */
	&asn_SPC_DL_FDPCH_InfoPerRL_r6_specs_1	/* Additional specs */
};

