/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CBS-DRX-Level1Information.h"

static int
memb_ctch_AllocationPeriod_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 256)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_cbs_FrameOffset_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
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

static asn_oer_constraints_t asn_OER_memb_ctch_AllocationPeriod_constr_2 CC_NOTUSED = {
	{ 2, 1 }	/* (1..256) */,
	-1};
static asn_per_constraints_t asn_PER_memb_ctch_AllocationPeriod_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  1,  256 }	/* (1..256) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_cbs_FrameOffset_constr_3 CC_NOTUSED = {
	{ 1, 1 }	/* (0..255) */,
	-1};
static asn_per_constraints_t asn_PER_memb_cbs_FrameOffset_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_CBS_DRX_Level1Information_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CBS_DRX_Level1Information, ctch_AllocationPeriod),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_ctch_AllocationPeriod_constr_2, &asn_PER_memb_ctch_AllocationPeriod_constr_2,  memb_ctch_AllocationPeriod_constraint_1 },
		0, 0, /* No default value */
		"ctch-AllocationPeriod"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CBS_DRX_Level1Information, cbs_FrameOffset),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_cbs_FrameOffset_constr_3, &asn_PER_memb_cbs_FrameOffset_constr_3,  memb_cbs_FrameOffset_constraint_1 },
		0, 0, /* No default value */
		"cbs-FrameOffset"
		},
};
static const ber_tlv_tag_t asn_DEF_CBS_DRX_Level1Information_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CBS_DRX_Level1Information_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ctch-AllocationPeriod */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* cbs-FrameOffset */
};
asn_SEQUENCE_specifics_t asn_SPC_CBS_DRX_Level1Information_specs_1 = {
	sizeof(struct CBS_DRX_Level1Information),
	offsetof(struct CBS_DRX_Level1Information, _asn_ctx),
	asn_MAP_CBS_DRX_Level1Information_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CBS_DRX_Level1Information = {
	"CBS-DRX-Level1Information",
	"CBS-DRX-Level1Information",
	&asn_OP_SEQUENCE,
	asn_DEF_CBS_DRX_Level1Information_tags_1,
	sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1)
		/sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1[0]), /* 1 */
	asn_DEF_CBS_DRX_Level1Information_tags_1,	/* Same as above */
	sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1)
		/sizeof(asn_DEF_CBS_DRX_Level1Information_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CBS_DRX_Level1Information_1,
	2,	/* Elements count */
	&asn_SPC_CBS_DRX_Level1Information_specs_1	/* Additional specs */
};
