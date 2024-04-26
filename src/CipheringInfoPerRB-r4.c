/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "CipheringInfoPerRB-r4.h"

static int
memb_dl_HFN_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size >= 20 && size <= 25)) {
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
memb_dl_UM_SN_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 7)) {
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
memb_ul_HFN_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size >= 20 && size <= 25)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_dl_HFN_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(20..25)) */};
static asn_per_constraints_t asn_PER_memb_dl_HFN_constr_3 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  20,  25 }	/* (SIZE(20..25)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_dl_UM_SN_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	7	/* (SIZE(7..7)) */};
static asn_per_constraints_t asn_PER_memb_dl_UM_SN_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  7,  7 }	/* (SIZE(7..7)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_ul_HFN_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(20..25)) */};
static asn_per_constraints_t asn_PER_memb_ul_HFN_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  20,  25 }	/* (SIZE(20..25)) */,
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_CipheringInfoPerRB_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CipheringInfoPerRB_r4, rb_Identity),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_Identity,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rb-Identity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CipheringInfoPerRB_r4, dl_HFN),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_dl_HFN_constr_3, &asn_PER_memb_dl_HFN_constr_3,  memb_dl_HFN_constraint_1 },
		0, 0, /* No default value */
		"dl-HFN"
		},
	{ ATF_POINTER, 1, offsetof(struct CipheringInfoPerRB_r4, dl_UM_SN),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_dl_UM_SN_constr_4, &asn_PER_memb_dl_UM_SN_constr_4,  memb_dl_UM_SN_constraint_1 },
		0, 0, /* No default value */
		"dl-UM-SN"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CipheringInfoPerRB_r4, ul_HFN),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ &asn_OER_memb_ul_HFN_constr_5, &asn_PER_memb_ul_HFN_constr_5,  memb_ul_HFN_constraint_1 },
		0, 0, /* No default value */
		"ul-HFN"
		},
};
static const int asn_MAP_CipheringInfoPerRB_r4_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_CipheringInfoPerRB_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CipheringInfoPerRB_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rb-Identity */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-HFN */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* dl-UM-SN */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* ul-HFN */
};
asn_SEQUENCE_specifics_t asn_SPC_CipheringInfoPerRB_r4_specs_1 = {
	sizeof(struct CipheringInfoPerRB_r4),
	offsetof(struct CipheringInfoPerRB_r4, _asn_ctx),
	asn_MAP_CipheringInfoPerRB_r4_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_CipheringInfoPerRB_r4_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CipheringInfoPerRB_r4 = {
	"CipheringInfoPerRB-r4",
	"CipheringInfoPerRB-r4",
	&asn_OP_SEQUENCE,
	asn_DEF_CipheringInfoPerRB_r4_tags_1,
	sizeof(asn_DEF_CipheringInfoPerRB_r4_tags_1)
		/sizeof(asn_DEF_CipheringInfoPerRB_r4_tags_1[0]), /* 1 */
	asn_DEF_CipheringInfoPerRB_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_CipheringInfoPerRB_r4_tags_1)
		/sizeof(asn_DEF_CipheringInfoPerRB_r4_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_CipheringInfoPerRB_r4_1,
	4,	/* Elements count */
	&asn_SPC_CipheringInfoPerRB_r4_specs_1	/* Additional specs */
};

