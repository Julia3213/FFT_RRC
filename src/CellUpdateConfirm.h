/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CellUpdateConfirm_H_
#define	_CellUpdateConfirm_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellUpdateConfirm-r3-IEs.h"
#include "CellUpdateConfirm-v3a0ext.h"
#include <BIT_STRING.h>
#include "CellUpdateConfirm-v4b0ext-IEs.h"
#include "CellUpdateConfirm-v590ext-IEs.h"
#include "CellUpdateConfirm-v5d0ext-IEs.h"
#include "CellUpdateConfirm-v690ext-IEs.h"
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include "CellUpdateConfirm-r4-IEs.h"
#include "CellUpdateConfirm-r5-IEs.h"
#include "CellUpdateConfirm-r6-IEs.h"
#include "CellUpdateConfirm-r7-IEs.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellUpdateConfirm_PR {
	CellUpdateConfirm_PR_NOTHING,	/* No components present */
	CellUpdateConfirm_PR_r3,
	CellUpdateConfirm_PR_later_than_r3
} CellUpdateConfirm_PR;
typedef enum CellUpdateConfirm__later_than_r3__criticalExtensions_PR {
	CellUpdateConfirm__later_than_r3__criticalExtensions_PR_NOTHING,	/* No components present */
	CellUpdateConfirm__later_than_r3__criticalExtensions_PR_r4,
	CellUpdateConfirm__later_than_r3__criticalExtensions_PR_criticalExtensions
} CellUpdateConfirm__later_than_r3__criticalExtensions_PR;
typedef enum CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR {
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR_r5,
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR_criticalExtensions
} CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR;
typedef enum CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_r6,
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR;
typedef enum CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_r7,
	CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR;

/* CellUpdateConfirm */
typedef struct CellUpdateConfirm {
	CellUpdateConfirm_PR present;
	union CellUpdateConfirm_u {
		struct CellUpdateConfirm__r3 {
			CellUpdateConfirm_r3_IEs_t	 cellUpdateConfirm_r3;
			struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions {
				CellUpdateConfirm_v3a0ext_t	 cellUpdateConfirm_v3a0ext;
				struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions {
					BIT_STRING_t	*cellUpdateConfirm_r3_add_ext	/* OPTIONAL */;
					struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions {
						CellUpdateConfirm_v4b0ext_IEs_t	 cellUpdateConfirm_v4b0ext;
						struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtenstions {
							CellUpdateConfirm_v590ext_IEs_t	 cellUpdateConfirm_v590ext;
							struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions {
								CellUpdateConfirm_v5d0ext_IEs_t	 cellUpdateConfirm_v5d0ext;
								struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
									CellUpdateConfirm_v690ext_IEs_t	 cellUpdateConfirm_v690ext;
									struct CellUpdateConfirm__r3__v3a0NonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *nonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v690NonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v5d0NonCriticalExtenstions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v590NonCriticalExtenstions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v4b0NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *laterNonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v3a0NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct CellUpdateConfirm__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct CellUpdateConfirm__later_than_r3__criticalExtensions {
				CellUpdateConfirm__later_than_r3__criticalExtensions_PR present;
				union CellUpdateConfirm__later_than_r3__criticalExtensions_u {
					struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4 {
						CellUpdateConfirm_r4_IEs_t	 cellUpdateConfirm_r4;
						struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions {
							BIT_STRING_t	*cellUpdateConfirm_r4_add_ext	/* OPTIONAL */;
							struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtenstions {
								CellUpdateConfirm_v590ext_IEs_t	 cellUpdateConfirm_v590ext;
								struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions {
									CellUpdateConfirm_v5d0ext_IEs_t	 cellUpdateConfirm_v5d0ext;
									struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
										CellUpdateConfirm_v690ext_IEs_t	 cellUpdateConfirm_v690ext;
										struct CellUpdateConfirm__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtenstions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *v690NonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v5d0NonCriticalExtenstions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v590NonCriticalExtenstions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v4d0NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} r4;
					struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions {
						CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_PR present;
						union CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions_u {
							struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__r5 {
								CellUpdateConfirm_r5_IEs_t	 cellUpdateConfirm_r5;
								BIT_STRING_t	*cellUpdateConfirm_r5_add_ext	/* OPTIONAL */;
								struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions {
									CellUpdateConfirm_v5d0ext_IEs_t	 cellUpdateConfirm_v5d0ext;
									struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
										CellUpdateConfirm_v690ext_IEs_t	 cellUpdateConfirm_v690ext;
										struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *v690NonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v5d0NonCriticalExtenstions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} r5;
							struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions {
								CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
								union CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_u {
									struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6 {
										CellUpdateConfirm_r6_IEs_t	 cellUpdateConfirm_r6;
										BIT_STRING_t	*cellUpdateConfirm_r6_add_ext	/* OPTIONAL */;
										struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} r6;
									struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
										CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
										union CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_u {
											struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7 {
												CellUpdateConfirm_r7_IEs_t	 cellUpdateConfirm_r7;
												BIT_STRING_t	*cellUpdateConfirm_r7_add_ext	/* OPTIONAL */;
												struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7__nonCriticalExtensions {
													
													/* Context for parsing across buffer boundaries */
													asn_struct_ctx_t _asn_ctx;
												} *nonCriticalExtensions;
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} r7;
											struct CellUpdateConfirm__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} criticalExtensions;
										} choice;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} criticalExtensions;
								} choice;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} criticalExtensions;
						} choice;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} criticalExtensions;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellUpdateConfirm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellUpdateConfirm;
extern asn_CHOICE_specifics_t asn_SPC_CellUpdateConfirm_specs_1;
extern asn_TYPE_member_t asn_MBR_CellUpdateConfirm_1[2];
extern asn_per_constraints_t asn_PER_type_CellUpdateConfirm_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _CellUpdateConfirm_H_ */
#include <asn_internal.h>
