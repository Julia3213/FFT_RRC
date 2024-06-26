/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioBearerReconfiguration_H_
#define	_RadioBearerReconfiguration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RadioBearerReconfiguration-r3-IEs.h"
#include "RadioBearerReconfiguration-v3a0ext.h"
#include <BIT_STRING.h>
#include "RadioBearerReconfiguration-v4b0ext-IEs.h"
#include "RadioBearerReconfiguration-v590ext-IEs.h"
#include "RadioBearerReconfiguration-v5d0ext-IEs.h"
#include "RadioBearerReconfiguration-v690ext-IEs.h"
#include <constr_SEQUENCE.h>
#include "RRC-TransactionIdentifier.h"
#include "RadioBearerReconfiguration-r4-IEs.h"
#include "RadioBearerReconfiguration-r5-IEs.h"
#include "RadioBearerReconfiguration-r6-IEs.h"
#include "RadioBearerReconfiguration-r7-IEs.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RadioBearerReconfiguration_PR {
	RadioBearerReconfiguration_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration_PR_r3,
	RadioBearerReconfiguration_PR_later_than_r3
} RadioBearerReconfiguration_PR;
typedef enum RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR {
	RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR_r4,
	RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR_criticalExtensions
} RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR;
typedef enum RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR {
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_r5,
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR_criticalExtensions
} RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR;
typedef enum RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_r6,
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR;
typedef enum RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_r7,
	RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR;

/* RadioBearerReconfiguration */
typedef struct RadioBearerReconfiguration {
	RadioBearerReconfiguration_PR present;
	union RadioBearerReconfiguration_u {
		struct RadioBearerReconfiguration__r3 {
			RadioBearerReconfiguration_r3_IEs_t	 radioBearerReconfiguration_r3;
			struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions {
				RadioBearerReconfiguration_v3a0ext_t	 radioBearerReconfiguration_v3a0ext;
				struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions {
					BIT_STRING_t	*radioBearerReconfiguration_r3_add_ext	/* OPTIONAL */;
					struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions {
						RadioBearerReconfiguration_v4b0ext_IEs_t	 radioBearerReconfiguration_v4b0ext;
						struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions {
							RadioBearerReconfiguration_v590ext_IEs_t	 radioBearerReconfiguration_v590ext;
							struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions {
								RadioBearerReconfiguration_v5d0ext_IEs_t	 radioBearerReconfiguration_v5d0ext;
								struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
									RadioBearerReconfiguration_v690ext_IEs_t	 radioBearerReconfiguration_v690ext;
									struct RadioBearerReconfiguration__r3__v3aoNonCriticalExtensions__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
										
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
						} *v590NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v4b0NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *laterNonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v3aoNonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct RadioBearerReconfiguration__later_than_r3 {
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct RadioBearerReconfiguration__later_than_r3__criticalExtensions {
				RadioBearerReconfiguration__later_than_r3__criticalExtensions_PR present;
				union RadioBearerReconfiguration__later_than_r3__criticalExtensions_u {
					struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4 {
						RadioBearerReconfiguration_r4_IEs_t	 radioBearerReconfiguration_r4;
						struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions {
							BIT_STRING_t	*radioBearerReconfiguration_r4_add_ext	/* OPTIONAL */;
							struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions {
								RadioBearerReconfiguration_v590ext_IEs_t	 radioBearerReconfiguration_v590ext;
								struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions {
									RadioBearerReconfiguration_v5d0ext_IEs_t	 radioBearerReconfiguration_v5d0ext;
									struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
										RadioBearerReconfiguration_v690ext_IEs_t	 radioBearerReconfiguration_v690ext;
										struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v590NonCriticalExtensions__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
											
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
							} *v590NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v4d0NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} r4;
					struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions {
						RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_PR present;
						union RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions_u {
							struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5 {
								RadioBearerReconfiguration_r5_IEs_t	 radioBearerReconfiguration_r5;
								BIT_STRING_t	*radioBearerReconfiguration_r5_add_ext	/* OPTIONAL */;
								struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions {
									RadioBearerReconfiguration_v5d0ext_IEs_t	 radioBearerReconfiguration_v5d0ext;
									struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions__v690NonCriticalExtensions {
										RadioBearerReconfiguration_v690ext_IEs_t	 radioBearerReconfiguration_v690ext;
										struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__r5__v5d0NonCriticalExtenstions__v690NonCriticalExtensions__nonCriticalExtensions {
											
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
							struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions {
								RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
								union RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_u {
									struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6 {
										RadioBearerReconfiguration_r6_IEs_t	 radioBearerReconfiguration_r6;
										BIT_STRING_t	*radioBearerReconfiguration_r6_add_ext	/* OPTIONAL */;
										struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r6__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} r6;
									struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
										RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
										union RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions_u {
											struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7 {
												RadioBearerReconfiguration_r7_IEs_t	 radioBearerReconfiguration_r7;
												struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__r7__nonCriticalExtensions {
													
													/* Context for parsing across buffer boundaries */
													asn_struct_ctx_t _asn_ctx;
												} *nonCriticalExtensions;
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} r7;
											struct RadioBearerReconfiguration__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
												
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
} RadioBearerReconfiguration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerReconfiguration;
extern asn_CHOICE_specifics_t asn_SPC_RadioBearerReconfiguration_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioBearerReconfiguration_1[2];
extern asn_per_constraints_t asn_PER_type_RadioBearerReconfiguration_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _RadioBearerReconfiguration_H_ */
#include <asn_internal.h>
