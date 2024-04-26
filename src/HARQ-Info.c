/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "HARQ-Info.h"

static int
memb_explicit_constraint_3(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 8)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_numberOfProcesses_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 8)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_explicit_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_type_explicit_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_explicit_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_memb_explicit_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_memoryPartitioning_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_memoryPartitioning_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_numberOfProcesses_constr_2 CC_NOTUSED = {
	{ 1, 1 }	/* (1..8) */,
	-1};
static asn_per_constraints_t asn_PER_memb_numberOfProcesses_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (1..8) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_explicit_5[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (10 << 2)),
		0,
		&asn_DEF_HARQMemorySize,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_explicit_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_explicit_specs_5 = {
	sizeof(struct HARQ_Info__memoryPartitioning__explicit),
	offsetof(struct HARQ_Info__memoryPartitioning__explicit, _asn_ctx),
	1,	/* XER encoding is XMLValueList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_explicit_5 = {
	"explicit",
	"explicit",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_explicit_tags_5,
	sizeof(asn_DEF_explicit_tags_5)
		/sizeof(asn_DEF_explicit_tags_5[0]) - 1, /* 1 */
	asn_DEF_explicit_tags_5,	/* Same as above */
	sizeof(asn_DEF_explicit_tags_5)
		/sizeof(asn_DEF_explicit_tags_5[0]), /* 2 */
	{ &asn_OER_type_explicit_constr_5, &asn_PER_type_explicit_constr_5, SEQUENCE_OF_constraint },
	asn_MBR_explicit_5,
	1,	/* Single element */
	&asn_SPC_explicit_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_memoryPartitioning_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HARQ_Info__memoryPartitioning, choice.implicit),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"implicit"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HARQ_Info__memoryPartitioning, choice.Explicit),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_explicit_5,
		0,
		{ &asn_OER_memb_explicit_constr_5, &asn_PER_memb_explicit_constr_5,  memb_explicit_constraint_3 },
		0, 0, /* No default value */
		"explicit"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_memoryPartitioning_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* implicit */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* explicit */
};
static asn_CHOICE_specifics_t asn_SPC_memoryPartitioning_specs_3 = {
	sizeof(struct HARQ_Info__memoryPartitioning),
	offsetof(struct HARQ_Info__memoryPartitioning, _asn_ctx),
	offsetof(struct HARQ_Info__memoryPartitioning, present),
	sizeof(((struct HARQ_Info__memoryPartitioning *)0)->present),
	asn_MAP_memoryPartitioning_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_memoryPartitioning_3 = {
	"memoryPartitioning",
	"memoryPartitioning",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_memoryPartitioning_constr_3, &asn_PER_type_memoryPartitioning_constr_3, CHOICE_constraint },
	asn_MBR_memoryPartitioning_3,
	2,	/* Elements count */
	&asn_SPC_memoryPartitioning_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_HARQ_Info_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HARQ_Info, numberOfProcesses),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_numberOfProcesses_constr_2, &asn_PER_memb_numberOfProcesses_constr_2,  memb_numberOfProcesses_constraint_1 },
		0, 0, /* No default value */
		"numberOfProcesses"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HARQ_Info, memoryPartitioning),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_memoryPartitioning_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"memoryPartitioning"
		},
};
static const ber_tlv_tag_t asn_DEF_HARQ_Info_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HARQ_Info_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* numberOfProcesses */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* memoryPartitioning */
};
asn_SEQUENCE_specifics_t asn_SPC_HARQ_Info_specs_1 = {
	sizeof(struct HARQ_Info),
	offsetof(struct HARQ_Info, _asn_ctx),
	asn_MAP_HARQ_Info_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_HARQ_Info = {
	"HARQ-Info",
	"HARQ-Info",
	&asn_OP_SEQUENCE,
	asn_DEF_HARQ_Info_tags_1,
	sizeof(asn_DEF_HARQ_Info_tags_1)
		/sizeof(asn_DEF_HARQ_Info_tags_1[0]), /* 1 */
	asn_DEF_HARQ_Info_tags_1,	/* Same as above */
	sizeof(asn_DEF_HARQ_Info_tags_1)
		/sizeof(asn_DEF_HARQ_Info_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_HARQ_Info_1,
	2,	/* Elements count */
	&asn_SPC_HARQ_Info_specs_1	/* Additional specs */
};
