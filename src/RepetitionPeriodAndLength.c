/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "RepetitionPeriodAndLength.h"

static int
memb_repetitionPeriod2_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value == 1)) {
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
memb_repetitionPeriod4_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 3)) {
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
memb_repetitionPeriod8_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 7)) {
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
memb_repetitionPeriod16_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 15)) {
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
memb_repetitionPeriod32_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 31)) {
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
memb_repetitionPeriod64_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 63)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_repetitionPeriod2_constr_3 CC_NOTUSED = {
	{ 1, 1 }	/* (1..1) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod2_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  1,  1 }	/* (1..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_repetitionPeriod4_constr_4 CC_NOTUSED = {
	{ 1, 1 }	/* (1..3) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod4_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  1,  3 }	/* (1..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_repetitionPeriod8_constr_5 CC_NOTUSED = {
	{ 1, 1 }	/* (1..7) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod8_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  1,  7 }	/* (1..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_repetitionPeriod16_constr_6 CC_NOTUSED = {
	{ 1, 1 }	/* (1..15) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod16_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  1,  15 }	/* (1..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_repetitionPeriod32_constr_7 CC_NOTUSED = {
	{ 1, 1 }	/* (1..31) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod32_constr_7 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 5,  5,  1,  31 }	/* (1..31) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_repetitionPeriod64_constr_8 CC_NOTUSED = {
	{ 1, 1 }	/* (1..63) */,
	-1};
static asn_per_constraints_t asn_PER_memb_repetitionPeriod64_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  1,  63 }	/* (1..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_RepetitionPeriodAndLength_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_RepetitionPeriodAndLength_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  6 }	/* (0..6) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_RepetitionPeriodAndLength_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"repetitionPeriod1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod2),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod2_constr_3, &asn_PER_memb_repetitionPeriod2_constr_3,  memb_repetitionPeriod2_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod2"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod4),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod4_constr_4, &asn_PER_memb_repetitionPeriod4_constr_4,  memb_repetitionPeriod4_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod8),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod8_constr_5, &asn_PER_memb_repetitionPeriod8_constr_5,  memb_repetitionPeriod8_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod8"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod16),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod16_constr_6, &asn_PER_memb_repetitionPeriod16_constr_6,  memb_repetitionPeriod16_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod16"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod32),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod32_constr_7, &asn_PER_memb_repetitionPeriod32_constr_7,  memb_repetitionPeriod32_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod32"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RepetitionPeriodAndLength, choice.repetitionPeriod64),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_repetitionPeriod64_constr_8, &asn_PER_memb_repetitionPeriod64_constr_8,  memb_repetitionPeriod64_constraint_1 },
		0, 0, /* No default value */
		"repetitionPeriod64"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_RepetitionPeriodAndLength_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* repetitionPeriod1 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* repetitionPeriod2 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* repetitionPeriod4 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* repetitionPeriod8 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* repetitionPeriod16 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* repetitionPeriod32 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* repetitionPeriod64 */
};
asn_CHOICE_specifics_t asn_SPC_RepetitionPeriodAndLength_specs_1 = {
	sizeof(struct RepetitionPeriodAndLength),
	offsetof(struct RepetitionPeriodAndLength, _asn_ctx),
	offsetof(struct RepetitionPeriodAndLength, present),
	sizeof(((struct RepetitionPeriodAndLength *)0)->present),
	asn_MAP_RepetitionPeriodAndLength_tag2el_1,
	7,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_RepetitionPeriodAndLength = {
	"RepetitionPeriodAndLength",
	"RepetitionPeriodAndLength",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_RepetitionPeriodAndLength_constr_1, &asn_PER_type_RepetitionPeriodAndLength_constr_1, CHOICE_constraint },
	asn_MBR_RepetitionPeriodAndLength_1,
	7,	/* Elements count */
	&asn_SPC_RepetitionPeriodAndLength_specs_1	/* Additional specs */
};

