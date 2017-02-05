#include <stdlib.h>
#include <map>
#include "pkcs11import.h"
#include "HsFFI.h"
#include "SoftHsm_stub.h"


#define VERSION_MAJOR CRYPTOKI_VERSION_MAJOR
#define VERSION_MINOR CRYPTOKI_VERSION_MINOR


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
    .C_DigestInit = &C_DigestInit,
    .C_Digest = &C_Digest,
    .C_DigestUpdate = &C_DigestUpdate,
    .C_DigestKey = &C_DigestKey,
    .C_DigestFinal = &C_DigestFinal,
    .C_SeedRandom = &C_SeedRandom,
    .C_GenerateRandom = &C_GenerateRandom,
    .C_GetFunctionStatus = &C_GetFunctionStatus,
    .C_CancelFunction = &C_CancelFunction,
    .C_WaitForSlotEvent = &C_WaitForSlotEvent,
};


typedef std::map<int, CK_SESSION_INFO> SessionsMap;
typedef SessionsMap::iterator SessionRef;


typedef std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO> MechanismsMap;


struct ModuleState {
    // this counter is incremented when new session is created
    // used to generate session ids
    int session_counter;

    // a map of session id to session information objects
    SessionsMap sessions;
    MechanismsMap mechanisms;
};


// used to store global module state
static ModuleState * g_module_state;


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR p_function_list)
{
    *p_function_list = &g_function_list;
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pReserved) {
    if (g_module_state == nullptr) {
        g_module_state = new ModuleState();

        g_module_state->mechanisms[CKM_SHA256] = CK_MECHANISM_INFO{.flags = CKF_DIGEST};

        int argc = 2;
        char plus_rts[] = "+RTS";
        char minus_a32m[] = "-A32m";
        char *argv[] = { plus_rts, minus_a32m, NULL };
        char **pargv = argv;

        // Initialize Haskell runtime
        hs_init(&argc, &pargv);

        return CKR_OK;
    } else {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    if (g_module_state == nullptr) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        delete g_module_state;
        g_module_state = nullptr;
        hs_exit();
        return CKR_OK;
    }
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
    if (g_module_state == nullptr) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        auto & mechs = g_module_state->mechanisms;
        if (pMechanismList == nullptr) {
            *pulCount = mechs.size();
            return CKR_OK;
        } else {
            if (*pulCount >= mechs.size()) {
                auto dest = pMechanismList;
                for (auto mech_pair : mechs) {
                    *dest = mech_pair.first;
                    dest++;
                }
                return CKR_OK;
            } else {
                *pulCount = mechs.size();
                return CKR_BUFFER_TOO_SMALL;
            }
        }
    }
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(
    CK_SLOT_ID            slotID,  /* ID of the token's slot */
    CK_MECHANISM_TYPE     type,    /* type of mechanism */
    CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
    if (g_module_state == nullptr) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        auto & mechs = g_module_state->mechanisms;
        auto pos = mechs.find(type);
        if (pos == mechs.end()) {
            return CKR_MECHANISM_INVALID;
        }
        *pInfo = pos->second;
        return CKR_OK;
    }
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
    if (g_module_state == nullptr) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        // TODO: should be atomic
        auto session_id = g_module_state->session_counter++;
        g_module_state->sessions[session_id] = CK_SESSION_INFO{.slotID = slotID, .flags = flags};
        *phSession = session_id;
        return CKR_OK;
    }
}


static CK_RV SessionOperation(CK_SESSION_HANDLE handle, std::function<CK_RV(SessionRef)> operation_fun) {
    if (g_module_state == nullptr) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    } else {
        auto pos = g_module_state->sessions.find(handle);
        if (pos == g_module_state->sessions.end()) {
            return CKR_SESSION_HANDLE_INVALID;
        } else {
            return operation_fun(pos);
        }
    }
}


static CK_RV CloseSession(SessionRef ref) {
    g_module_state->sessions.erase(ref);
    return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    auto closer = [](SessionRef ref){
        g_module_state->sessions.erase(ref);
        return CKR_OK;
    };
    return SessionOperation(hSession, closer);
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
    return SessionOperation(hSession, [pInfo](SessionRef ref) {
        *pInfo = ref->second;
        return CKR_OK;
    });
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


/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(
    CK_SESSION_HANDLE hSession,   /* the session's handle */
    CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
    return SessionOperation(hSession, [pMechanism](SessionRef ref){
        return digestInit(&ref->second, pMechanism->mechanism);
    });
}


/* C_Digest digests data in a single part. */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(
    CK_SESSION_HANDLE hSession,     /* the session's handle */
    CK_BYTE_PTR       pData,        /* data to be digested */
    CK_ULONG          ulDataLen,    /* bytes of data to digest */
    CK_BYTE_PTR       pDigest,      /* gets the message digest */
    CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
    return SessionOperation(hSession, [pData, ulDataLen, pDigest, pulDigestLen](SessionRef ref){
        return digest(&ref->second, pData, ulDataLen, pDigest, pulDigestLen);
    });
}


/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pPart,     /* data to be digested */
    CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(
    CK_SESSION_HANDLE hSession,     /* the session's handle */
    CK_BYTE_PTR       pDigest,      /* gets the message digest */
    CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
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
    return CKR_RANDOM_NO_RNG;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_BYTE_PTR       RandomData,  /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    return CKR_RANDOM_NO_RNG;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
    CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
    CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
    return CKR_FUNCTION_NOT_PARALLEL;
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
