/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "TransmissionRLC-Discard.h"

static asn_oer_constraints_t asn_OER_type_TransmissionRLC_Discard_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_TransmissionRLC_Discard_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_TransmissionRLC_Discard_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct TransmissionRLC_Discard, choice.timerBasedExplicit),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExplicitDiscard,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timerBasedExplicit"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransmissionRLC_Discard, choice.timerBasedNoExplicit),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NoExplicitDiscard,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"timerBasedNoExplicit"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransmissionRLC_Discard, choice.maxDAT_Retransmissions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxDAT_Retransmissions,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"maxDAT-Retransmissions"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct TransmissionRLC_Discard, choice.noDiscard),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxDAT,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"noDiscard"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_TransmissionRLC_Discard_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timerBasedExplicit */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* timerBasedNoExplicit */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* maxDAT-Retransmissions */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* noDiscard */
};
asn_CHOICE_specifics_t asn_SPC_TransmissionRLC_Discard_specs_1 = {
	sizeof(struct TransmissionRLC_Discard),
	offsetof(struct TransmissionRLC_Discard, _asn_ctx),
	offsetof(struct TransmissionRLC_Discard, present),
	sizeof(((struct TransmissionRLC_Discard *)0)->present),
	asn_MAP_TransmissionRLC_Discard_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_TransmissionRLC_Discard = {
	"TransmissionRLC-Discard",
	"TransmissionRLC-Discard",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_TransmissionRLC_Discard_constr_1, &asn_PER_type_TransmissionRLC_Discard_constr_1, CHOICE_constraint },
	asn_MBR_TransmissionRLC_Discard_1,
	4,	/* Elements count */
	&asn_SPC_TransmissionRLC_Discard_specs_1	/* Additional specs */
};

