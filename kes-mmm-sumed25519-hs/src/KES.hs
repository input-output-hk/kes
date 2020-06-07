{-# LANGUAGE PatternSynonyms #-}
module KES
    ( verify
    , generate
    , sign
    , t
    , update
    , compute_public
    , pattern SIGNATURE_SIZE
    , pattern SECRET_KEY_SIZE
    , pattern PUBLIC_KEY_SIZE
    ) where

import Data.Word
import Foreign.Ptr
import Foreign.C.Types (CChar)

pattern SIGNATURE_SIZE = 484
pattern SECRET_KEY_SIZE = 1220
pattern PUBLIC_KEY_SIZE = 32

foreign import ccall "kes_mmm_sumed25519_version" version
    :: Ptr CChar

foreign import ccall "kes_mmm_sumed25519_publickey_verify" verify
    :: Ptr Word8 -- ^ public key bytes pointer
    -> Ptr Word8 -- ^ message bytes pointer
    -> IntPtr -- ^ message size
    -> Ptr Word8 -- ^ signature bytes pointer
    -> Bool

foreign import ccall "kes_mmm_sumed25519_secretkey_generate" generate
    :: Ptr Word8 -- ^ seed pointer
    -> Ptr Word8 -- ^ secret bytes buffer
    -> Ptr Word8 -- ^ public bytes buffer
    -> IO ()

foreign import ccall "kes_mmm_sumed25519_secretkey_sign" sign
    :: Ptr Word8 -- ^ secret bytes pointer
    -> Ptr Word8 -- ^ message bytes pointer
    -> IntPtr    -- ^ message size
    -> Ptr Word8 -- ^ signature buffer
    -> IO ()

foreign import ccall "kes_mmm_sumed25519_secretkey_compute_public" compute_public
    :: Ptr Word8 -- ^ secret bytes pointer
    -> Ptr Word8 -- ^ public bytes pointer
    -> IO ()

foreign import ccall "kes_mmm_sumed25519_secretkey_t" t
    :: Ptr Word8 -- ^ secret bytes pointer
    -> Word32

foreign import ccall "kes_mmm_sumed25519_secretkey_update" update
    :: Ptr Word8 -- ^ secret bytes buffer
    -> IO ()
