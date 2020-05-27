-- |
-- Module      : Crypto.PubKey.HPKE.AEAD
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE RankNTypes #-}
module Crypto.PubKey.HPKE.AEAD
    ( AeadID
    , AEAD(..)
    , KeyAEAD
    , NonceAEAD
    , RunAEAD
    ) where

import Crypto.Cipher.Types (AuthTag)

import Crypto.PubKey.HPKE.Imports

-- | AEAD encryption algorithm identifier.
type AeadID = Word16

type KeyAEAD = ScrubbedBytes
type NonceAEAD = Bytes

type RunAEAD aad ba = NonceAEAD -> ba -> aad -> (ba, AuthTag)

-- | An AEAD encryption algorithm.
data AEAD = AEAD
    { aeadID          :: AeadID  -- ^ Return the identifier of the AEAD algorithm.
    , aeadName        :: String  -- ^ Return the name of the AEAD algorithm.
    , aeadNk          :: Int
    , aeadNn          :: Int
    , aeadAuthTagLen  :: Int
    , aeadEncryptF    :: forall aad ba . (ByteArrayAccess aad, ByteArray ba) => KeyAEAD -> RunAEAD aad ba
    , aeadDecryptF    :: forall aad ba . (ByteArrayAccess aad, ByteArray ba) => KeyAEAD -> RunAEAD aad ba
    }

instance Show AEAD where
    show = aeadName

instance Eq AEAD where
    a1 == a2 = aeadID a1 == aeadID a2
