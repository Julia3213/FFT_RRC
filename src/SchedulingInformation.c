/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SchedulingInformation.h"

#include "SibOFF-List.h"
static int
memb_rep4_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1)) {
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
memb_rep8_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 3)) {
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
memb_rep16_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 7)) {
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
memb_rep32_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 15)) {
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
memb_rep64_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 31)) {
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
memb_rep128_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 63)) {
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
memb_rep256_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 127)) {
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
memb_rep512_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
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

static int
memb_rep1024_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 511)) {
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
memb_rep2048_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1023)) {
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
memb_rep4096_constraint_4(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 2047)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_rep4_constr_5 CC_NOTUSED = {
	{ 1, 1 }	/* (0..1) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep4_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep8_constr_6 CC_NOTUSED = {
	{ 1, 1 }	/* (0..3) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep8_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep16_constr_7 CC_NOTUSED = {
	{ 1, 1 }	/* (0..7) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep16_constr_7 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep32_constr_8 CC_NOTUSED = {
	{ 1, 1 }	/* (0..15) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep32_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep64_constr_9 CC_NOTUSED = {
	{ 1, 1 }	/* (0..31) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep64_constr_9 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 5,  5,  0,  31 }	/* (0..31) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep128_constr_10 CC_NOTUSED = {
	{ 1, 1 }	/* (0..63) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep128_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  0,  63 }	/* (0..63) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep256_constr_11 CC_NOTUSED = {
	{ 1, 1 }	/* (0..127) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep256_constr_11 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0,  127 }	/* (0..127) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep512_constr_12 CC_NOTUSED = {
	{ 1, 1 }	/* (0..255) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep512_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep1024_constr_13 CC_NOTUSED = {
	{ 2, 1 }	/* (0..511) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep1024_constr_13 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 9,  9,  0,  511 }	/* (0..511) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep2048_constr_14 CC_NOTUSED = {
	{ 2, 1 }	/* (0..1023) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep2048_constr_14 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 10,  10,  0,  1023 }	/* (0..1023) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_rep4096_constr_15 CC_NOTUSED = {
	{ 2, 1 }	/* (0..2047) */,
	-1};
static asn_per_constraints_t asn_PER_memb_rep4096_constr_15 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 11,  11,  0,  2047 }	/* (0..2047) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_sib_Pos_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_sib_Pos_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  10 }	/* (0..10) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static int asn_DFL_3_cmp_1(const void *sptr) {
	const SegCount_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 1 */
	return (*st != 1);
}
static int asn_DFL_3_set_1(void **sptr) {
	SegCount_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 1 */
	*st = 1;
	return 0;
}
static asn_TYPE_member_t asn_MBR_sib_Pos_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep4),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep4_constr_5, &asn_PER_memb_rep4_constr_5,  memb_rep4_constraint_4 },
		0, 0, /* No default value */
		"rep4"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep8),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep8_constr_6, &asn_PER_memb_rep8_constr_6,  memb_rep8_constraint_4 },
		0, 0, /* No default value */
		"rep8"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep16),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep16_constr_7, &asn_PER_memb_rep16_constr_7,  memb_rep16_constraint_4 },
		0, 0, /* No default value */
		"rep16"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep32),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep32_constr_8, &asn_PER_memb_rep32_constr_8,  memb_rep32_constraint_4 },
		0, 0, /* No default value */
		"rep32"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep64),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep64_constr_9, &asn_PER_memb_rep64_constr_9,  memb_rep64_constraint_4 },
		0, 0, /* No default value */
		"rep64"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep128),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep128_constr_10, &asn_PER_memb_rep128_constr_10,  memb_rep128_constraint_4 },
		0, 0, /* No default value */
		"rep128"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep256),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep256_constr_11, &asn_PER_memb_rep256_constr_11,  memb_rep256_constraint_4 },
		0, 0, /* No default value */
		"rep256"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep512),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep512_constr_12, &asn_PER_memb_rep512_constr_12,  memb_rep512_constraint_4 },
		0, 0, /* No default value */
		"rep512"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep1024),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep1024_constr_13, &asn_PER_memb_rep1024_constr_13,  memb_rep1024_constraint_4 },
		0, 0, /* No default value */
		"rep1024"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep2048),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep2048_constr_14, &asn_PER_memb_rep2048_constr_14,  memb_rep2048_constraint_4 },
		0, 0, /* No default value */
		"rep2048"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling__sib_Pos, choice.rep4096),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_rep4096_constr_15, &asn_PER_memb_rep4096_constr_15,  memb_rep4096_constraint_4 },
		0, 0, /* No default value */
		"rep4096"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_sib_Pos_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rep4 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* rep8 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* rep16 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* rep32 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* rep64 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* rep128 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* rep256 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* rep512 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* rep1024 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* rep2048 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 } /* rep4096 */
};
static asn_CHOICE_specifics_t asn_SPC_sib_Pos_specs_4 = {
	sizeof(struct SchedulingInformation__scheduling__sib_Pos),
	offsetof(struct SchedulingInformation__scheduling__sib_Pos, _asn_ctx),
	offsetof(struct SchedulingInformation__scheduling__sib_Pos, present),
	sizeof(((struct SchedulingInformation__scheduling__sib_Pos *)0)->present),
	asn_MAP_sib_Pos_tag2el_4,
	11,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_sib_Pos_4 = {
	"sib-Pos",
	"sib-Pos",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_sib_Pos_constr_4, &asn_PER_type_sib_Pos_constr_4, CHOICE_constraint },
	asn_MBR_sib_Pos_4,
	11,	/* Elements count */
	&asn_SPC_sib_Pos_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_scheduling_2[] = {
	{ ATF_POINTER, 1, offsetof(struct SchedulingInformation__scheduling, segCount),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SegCount,
		0,
		{ 0, 0, 0 },
		&asn_DFL_3_cmp_1,	/* Compare DEFAULT 1 */
		&asn_DFL_3_set_1,	/* Set DEFAULT 1 */
		"segCount"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation__scheduling, sib_Pos),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_sib_Pos_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sib-Pos"
		},
	{ ATF_POINTER, 1, offsetof(struct SchedulingInformation__scheduling, sib_PosOffsetInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SibOFF_List,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sib-PosOffsetInfo"
		},
};
static const int asn_MAP_scheduling_oms_2[] = { 0, 2 };
static const ber_tlv_tag_t asn_DEF_scheduling_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_scheduling_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* segCount */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sib-Pos */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* sib-PosOffsetInfo */
};
static asn_SEQUENCE_specifics_t asn_SPC_scheduling_specs_2 = {
	sizeof(struct SchedulingInformation__scheduling),
	offsetof(struct SchedulingInformation__scheduling, _asn_ctx),
	asn_MAP_scheduling_tag2el_2,
	3,	/* Count of tags in the map */
	asn_MAP_scheduling_oms_2,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_scheduling_2 = {
	"scheduling",
	"scheduling",
	&asn_OP_SEQUENCE,
	asn_DEF_scheduling_tags_2,
	sizeof(asn_DEF_scheduling_tags_2)
		/sizeof(asn_DEF_scheduling_tags_2[0]) - 1, /* 1 */
	asn_DEF_scheduling_tags_2,	/* Same as above */
	sizeof(asn_DEF_scheduling_tags_2)
		/sizeof(asn_DEF_scheduling_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_scheduling_2,
	3,	/* Elements count */
	&asn_SPC_scheduling_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_SchedulingInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SchedulingInformation, scheduling),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_scheduling_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scheduling"
		},
};
static const ber_tlv_tag_t asn_DEF_SchedulingInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SchedulingInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* scheduling */
};
asn_SEQUENCE_specifics_t asn_SPC_SchedulingInformation_specs_1 = {
	sizeof(struct SchedulingInformation),
	offsetof(struct SchedulingInformation, _asn_ctx),
	asn_MAP_SchedulingInformation_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_SchedulingInformation = {
	"SchedulingInformation",
	"SchedulingInformation",
	&asn_OP_SEQUENCE,
	asn_DEF_SchedulingInformation_tags_1,
	sizeof(asn_DEF_SchedulingInformation_tags_1)
		/sizeof(asn_DEF_SchedulingInformation_tags_1[0]), /* 1 */
	asn_DEF_SchedulingInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_SchedulingInformation_tags_1)
		/sizeof(asn_DEF_SchedulingInformation_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SchedulingInformation_1,
	1,	/* Elements count */
	&asn_SPC_SchedulingInformation_specs_1	/* Additional specs */
};

