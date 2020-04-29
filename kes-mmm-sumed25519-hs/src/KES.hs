module KES
    ( verify
    , generate
    , sign
    , t
    , update
    ) where

import Data.Word
import Foreign.Ptr

foreign import ccall "ouroboros_kes_publickey_verify" verify
    :: Ptr Word8 -- ^ public key bytes pointer
    -> Ptr Word8 -- ^ message bytes pointer
    -> IntPtr -- ^ message size 
    -> Ptr Word8 -- ^ signature bytes pointer
    -> Bool

foreign import ccall "ouroboros_kes_secretkey_generate" generate
    :: Ptr Word8 -- ^ seed pointer
    -> Ptr Word8 -- ^ secret bytes buffer
    -> Ptr Word8 -- ^ public bytes buffer
    -> IO ()

foreign import ccall "ouroboros_kes_secretkey_sign" sign
    :: Ptr Word8 -- ^ secret bytes pointer
    -> Ptr Word8 -- ^ message bytes pointer
    -> IntPtr    -- ^ message size
    -> Ptr Word8 -- ^ signature buffer
    -> IO ()

foreign import ccall "ouroboros_kes_secretkey_t" t
    :: Ptr Word8 -- ^ secret bytes pointer
    -> Word32

foreign import ccall "void ouroboros_kes_secretkey_update" update
    :: Ptr Word8 -- ^ secret bytes buffer
    -> IO ()
