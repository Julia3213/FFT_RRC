/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "DownlinkTimeslotsCodes.h"

#include "DownlinkAdditionalTimeslots.h"
static int
memb_consecutive_constraint_6(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 13)) {
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
memb_timeslotList_constraint_6(const asn_TYPE_descriptor_t *td, const void *sptr,
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
	
	if((size >= 1 && size <= 13)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_timeslotList_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..13)) */};
static asn_per_constraints_t asn_PER_type_timeslotList_constr_8 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 4,  4,  1,  13 }	/* (SIZE(1..13)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_consecutive_constr_7 CC_NOTUSED = {
	{ 1, 1 }	/* (1..13) */,
	-1};
static asn_per_constraints_t asn_PER_memb_consecutive_constr_7 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  1,  13 }	/* (1..13) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_timeslotList_constr_8 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..13)) */};
static asn_per_constraints_t asn_PER_memb_timeslotList_constr_8 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 4,  4,  1,  13 }	/* (SIZE(1..13)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_additionalTimeslots_constr_6 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_additionalTimeslots_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_moreTimeslots_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_type_moreTimeslots_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_timeslotList_8[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_DownlinkAdditionalTimeslots,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_timeslotList_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_timeslotList_specs_8 = {
	sizeof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots__timeslotList),
	offsetof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots__timeslotList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_timeslotList_8 = {
	"timeslotList",
	"timeslotList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_timeslotList_tags_8,
	sizeof(asn_DEF_timeslotList_tags_8)
		/sizeof(asn_DEF_timeslotList_tags_8[0]) - 1, /* 1 */
	asn_DEF_timeslotList_tags_8,	/* Same as above */
	sizeof(asn_DEF_timeslotList_tags_8)
		/sizeof(asn_DEF_timeslotList_tags_8[0]), /* 2 */
	{ &asn_OER_type_timeslotList_constr_8, &asn_PER_type_timeslotList_constr_8, SEQUENCE_OF_constraint },
	asn_MBR_timeslotList_8,
	1,	/* Single element */
	&asn_SPC_timeslotList_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_additionalTimeslots_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots, choice.consecutive),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_consecutive_constr_7, &asn_PER_memb_consecutive_constr_7,  memb_consecutive_constraint_6 },
		0, 0, /* No default value */
		"consecutive"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots, choice.timeslotList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_timeslotList_8,
		0,
		{ &asn_OER_memb_timeslotList_constr_8, &asn_PER_memb_timeslotList_constr_8,  memb_timeslotList_constraint_6 },
		0, 0, /* No default value */
		"timeslotList"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_additionalTimeslots_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* consecutive */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* timeslotList */
};
static asn_CHOICE_specifics_t asn_SPC_additionalTimeslots_specs_6 = {
	sizeof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots),
	offsetof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots, _asn_ctx),
	offsetof(struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots, present),
	sizeof(((struct DownlinkTimeslotsCodes__moreTimeslots__additionalTimeslots *)0)->present),
	asn_MAP_additionalTimeslots_tag2el_6,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_additionalTimeslots_6 = {
	"additionalTimeslots",
	"additionalTimeslots",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_additionalTimeslots_constr_6, &asn_PER_type_additionalTimeslots_constr_6, CHOICE_constraint },
	asn_MBR_additionalTimeslots_6,
	2,	/* Elements count */
	&asn_SPC_additionalTimeslots_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_moreTimeslots_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes__moreTimeslots, choice.noMore),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"noMore"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes__moreTimeslots, choice.additionalTimeslots),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_additionalTimeslots_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"additionalTimeslots"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_moreTimeslots_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* noMore */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* additionalTimeslots */
};
static asn_CHOICE_specifics_t asn_SPC_moreTimeslots_specs_4 = {
	sizeof(struct DownlinkTimeslotsCodes__moreTimeslots),
	offsetof(struct DownlinkTimeslotsCodes__moreTimeslots, _asn_ctx),
	offsetof(struct DownlinkTimeslotsCodes__moreTimeslots, present),
	sizeof(((struct DownlinkTimeslotsCodes__moreTimeslots *)0)->present),
	asn_MAP_moreTimeslots_tag2el_4,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_moreTimeslots_4 = {
	"moreTimeslots",
	"moreTimeslots",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_moreTimeslots_constr_4, &asn_PER_type_moreTimeslots_constr_4, CHOICE_constraint },
	asn_MBR_moreTimeslots_4,
	2,	/* Elements count */
	&asn_SPC_moreTimeslots_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_DownlinkTimeslotsCodes_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes, firstIndividualTimeslotInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IndividualTimeslotInfo,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"firstIndividualTimeslotInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes, dl_TS_ChannelisationCodesShort),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCodesShort,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-TS-ChannelisationCodesShort"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkTimeslotsCodes, moreTimeslots),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_moreTimeslots_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"moreTimeslots"
		},
};
static const ber_tlv_tag_t asn_DEF_DownlinkTimeslotsCodes_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DownlinkTimeslotsCodes_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* firstIndividualTimeslotInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-TS-ChannelisationCodesShort */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* moreTimeslots */
};
asn_SEQUENCE_specifics_t asn_SPC_DownlinkTimeslotsCodes_specs_1 = {
	sizeof(struct DownlinkTimeslotsCodes),
	offsetof(struct DownlinkTimeslotsCodes, _asn_ctx),
	asn_MAP_DownlinkTimeslotsCodes_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DownlinkTimeslotsCodes = {
	"DownlinkTimeslotsCodes",
	"DownlinkTimeslotsCodes",
	&asn_OP_SEQUENCE,
	asn_DEF_DownlinkTimeslotsCodes_tags_1,
	sizeof(asn_DEF_DownlinkTimeslotsCodes_tags_1)
		/sizeof(asn_DEF_DownlinkTimeslotsCodes_tags_1[0]), /* 1 */
	asn_DEF_DownlinkTimeslotsCodes_tags_1,	/* Same as above */
	sizeof(asn_DEF_DownlinkTimeslotsCodes_tags_1)
		/sizeof(asn_DEF_DownlinkTimeslotsCodes_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DownlinkTimeslotsCodes_1,
	3,	/* Elements count */
	&asn_SPC_DownlinkTimeslotsCodes_specs_1	/* Additional specs */
};

