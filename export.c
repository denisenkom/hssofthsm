#include <stdlib.h>
#include "pkcs11import.h"
#include "HsFFI.h"


#define VERSION_MAJOR 2
#define VERSION_MINOR 1


static CK_FUNCTION_LIST g_function_list = {
    .version = {VERSION_MAJOR, VERSION_MINOR},
    .C_Initialize = &C_Initialize,
    .C_Finalize = &C_Finalize,
    .C_GetInfo = &C_GetInfo,
    .C_GetFunctionList = &C_GetFunctionList,
    .C_GetSlotList = &C_GetSlotList,
    .C_GetSlotInfo = &C_GetSlotInfo,
    .C_GetTokenInfo = &C_GetTokenInfo,
    .C_GetMechanismList = &C_GetMechanismList,
    .C_GetMechanismInfo = &C_GetMechanismInfo,
    .C_OpenSession = &C_OpenSession,
    .C_CloseSession = &C_CloseSession,
    .C_CloseAllSessions = &C_CloseAllSessions,
    .C_GetSessionInfo = &C_GetSessionInfo,
    .C_GetOperationState = &C_GetOperationState,
    .C_FindObjects = &C_FindObjects,
    .C_SeedRandom = &C_SeedRandom,
    .C_GenerateRandom = &C_GenerateRandom,
    .C_GetFunctionStatus = &C_GetFunctionStatus,
    .C_CancelFunction = &C_CancelFunction,
    .C_WaitForSlotEvent = &C_WaitForSlotEvent,
};


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR p_function_list)
{
    *p_function_list = &g_function_list;
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pReserved)
{
    int argc = 2;
    char *argv[] = { "+RTS", "-A32m", NULL };
    char **pargv = argv;

    // Initialize Haskell runtime
    hs_init(&argc, &pargv);

    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)()
{
    hs_exit();
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR p_info)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL 	  tokenPresent,
                                         CK_SLOT_ID_PTR 	  pSlotList,
                                         CK_ULONG_PTR 	  pulCount)
{
    CK_RV rv = CKR_OK;
    if (pSlotList == 0) {
    } else {
        if (*pulCount > 0) {
            pSlotList[0] = 0;
        } else {
            rv = CKR_BUFFER_TOO_SMALL;
        }
    }
    *pulCount = 1;
    return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
    CK_SLOT_ID       slotID,  /* the ID of the slot */
    CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
    CK_SLOT_ID        slotID,  /* ID of the token's slot */
    CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(
    CK_SLOT_ID            slotID,          /* ID of token's slot */
    CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
    CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(
    CK_SLOT_ID            slotID,  /* ID of the token's slot */
    CK_MECHANISM_TYPE     type,    /* type of mechanism */
    CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(
    CK_SLOT_ID            slotID,        /* the slot's ID */
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    *phSession = 0;
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
    CK_SLOT_ID     slotID  /* the token's slot */
)
{
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(
    CK_SESSION_HANDLE   hSession,  /* the session's handle */
    CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
    CK_SESSION_HANDLE hSession,             /* session's handle */
    CK_BYTE_PTR       pOperationState,      /* gets state */
    CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(
    CK_SESSION_HANDLE    hSession,          /* session's handle */
    CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
    CK_ULONG             ulMaxObjectCount,  /* max handles to get */
    CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pSeed,     /* the seed material */
    CK_ULONG          ulSeedLen  /* length of seed material */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_BYTE_PTR       RandomData,  /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
    CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
    CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
    CK_FLAGS flags,        /* blocking/nonblocking flag */
    CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
    CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}
