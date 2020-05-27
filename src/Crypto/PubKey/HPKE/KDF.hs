-- |
-- Module      : Crypto.PubKey.HPKE.KDF
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RankNTypes #-}
module Crypto.PubKey.HPKE.KDF
    ( KdfID
    , KDF(..)
    , withKDF
    , kdfNh
    ) where

import Crypto.Hash

import Crypto.PubKey.HPKE.Imports

-- | Key Derivation Function (KDF) identifier.
type KdfID  = Word16

-- | A Key Derivation Function (KDF).
data KDF = forall hash . HashAlgorithm hash => KDF
    { kdfID    :: KdfID   -- ^ Return the identifier of the KDF.
    , kdfName  :: String  -- ^ Return the name of the KDF.
    , kdfHash  :: hash
    }

instance Show KDF where
    show = kdfName

instance Eq KDF where
    k1 == k2 = kdfID k1 == kdfID k2

withHash :: HashAlgorithm hash'
         => hash'
         -> (forall hash . HashAlgorithm hash => f hash)
         -> (forall hash . HashAlgorithm hash => f hash -> a)
         -> a
withHash h gen use = use (witness h gen)
  where
    witness :: ty -> f ty -> f ty
    witness _ = id

withKDF :: KDF
        -> (forall hash . HashAlgorithm hash => f hash)
        -> (forall hash . HashAlgorithm hash => f hash -> a)
        -> a
withKDF KDF{kdfHash = h} = withHash h

kdfNh :: KDF -> Int
kdfNh KDF{ kdfHash = h } = hashDigestSize h
