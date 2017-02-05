module System.Crypto.SoftHsm
where

--import qualified Data.HashTable.IO as H
import Data.IORef
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Foreign.C.Types
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import System.Crypto.Pkcs11Imports

import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as UnsafeBs

import qualified Crypto.Hash.SHA256 as SHA256

--type HashTable k v = H.BasicHashTable k v


data OperationState = NoOperation | DigestState MechType


data SessionState = SessionState {
    sessionCounter :: Int,
    --sessionsHash :: HashTable Int SessionState
    operationState :: OperationState
}

instance Storable SessionState where
    sizeOf v = sizeOf $ sessionCounter v
    alignment _ = 1
    peek ptr = do
        ctr <- peek (castPtr ptr :: Ptr Int)
        return $ SessionState ctr NoOperation
    poke ptr val = do
        poke (castPtr ptr :: Ptr Int) (fromIntegral $ sessionCounter val)

--makeCounter :: IO Counter
--makeCounter = do
--    r <- newIORef 0
--    return (\i -> do atomicModifyIORef' r (+i)
--                     readIORef r)


digestInitTran NoOperation method = Right (DigestState method)
digestInitTran _ method = Left CKR_OPERATION_ACTIVE


foreign export ccall digestInit :: Ptr SessionState -> CK_MECHANISM_TYPE -> IO CK_RV
digestInit moduleStatePtr mechType = do
    if fromIntegral mechType == fromEnum Sha256
        then return $ toRv CKR_OK
        else return $ toRv CKR_MECHANISM_INVALID


foreign export ccall digest :: Ptr SessionState -> Ptr CChar -> CK_ULONG -> Ptr CChar -> Ptr CK_ULONG -> IO CK_RV
digest :: Ptr SessionState -> Ptr CChar -> CK_ULONG -> Ptr CChar -> Ptr CK_ULONG -> IO CK_RV
digest moduleStatePtr inBuf inBufLen outBuf outBufLenPtr = do
    inBs <- UnsafeBs.unsafePackCStringLen (inBuf, fromIntegral inBufLen)
    let outBs = SHA256.hash inBs
        outBsLen = BS.length outBs
    outBufLen <- peek outBufLenPtr
    if outBuf == nullPtr
        then do
            poke outBufLenPtr (fromIntegral outBsLen)
            return $ toRv CKR_OK
        else if outBsLen <= fromIntegral outBufLen
            then do
                UnsafeBs.unsafeUseAsCString outBs (\outBsCstr -> copyBytes outBuf outBsCstr outBsLen)
                poke outBufLenPtr (fromIntegral outBsLen)
                return $ toRv CKR_OK
            else return $ toRv CKR_BUFFER_TOO_SMALL
