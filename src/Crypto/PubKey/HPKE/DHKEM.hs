-- |
-- Module      : Crypto.PubKey.HPKE.DHKEM
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.PubKey.HPKE.DHKEM
    ( DHKEM
    , GroupKEM(..)
    , GroupStaticKEM(..)
    , GroupDeriveKEM(..)
    ) where

import qualified Data.ByteArray as B

import           Crypto.ECC
import           Crypto.Error
import           Crypto.Random

import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.KEM
import Crypto.PubKey.HPKE.Label
import Crypto.PubKey.HPKE.Imports

import Data.Kind (Type)
import Data.Proxy

-- | A KEM based on a Diffie-Hellman group.
data DHKEM group

unDHKEM :: proxy (DHKEM group) -> Proxy group
unDHKEM _ = Proxy

extractAndExpand :: KDF -> SharedSecret -> [ByteString] -> Zz
extractAndExpand kdf dh kemContext =
    withKDF kdf (labeledExtract ("dh" :) dh) $ \prk ->
        labeledExpand prk "prk" kemContext nzz
  where nzz = kdfNh kdf

groupCombine :: GroupKEM group
             => proxy group -> Enc -> GroupPublic group -> SharedSecret -> Zz
groupCombine grp enc pkR dh =
    let kdf = groupKDF grp
        pkRm = groupSerialize grp pkR
        kemContext = [ enc, pkRm ]
     in extractAndExpand kdf dh kemContext

groupEncap :: (GroupKEM group, MonadRandom r)
           => proxy group -> GroupPublic group -> r (CryptoFailable Zz, Enc)
groupEncap grp pkR = do
    (skE, pkE) <- groupGenerateKeyPair grp
    let mDh  = groupGetShared grp pkR skE
        enc  = groupSerialize grp pkE
        mZz  = groupCombine grp enc pkR <$> mDh
    return (mZz, enc)

groupDecap :: GroupKEM group
           => proxy group -> Enc -> GroupPrivate group -> GroupPublic group -> CryptoFailable Zz
groupDecap grp enc skR pkR = do
    pkE <- groupDeserialize grp enc
    let mDh = groupGetShared grp pkE skR
    groupCombine grp enc pkR <$> mDh

groupAuthCombine :: GroupKEM group
                 => proxy group -> Enc -> GroupPublic group -> GroupPublic group -> SharedSecret -> SharedSecret -> Zz
groupAuthCombine grp enc pkR pkS (SharedSecret dh1) (SharedSecret dh2) =
    let kdf = groupKDF grp
        pkRm = groupSerialize grp pkR
        pkSm = groupSerialize grp pkS
        kemContext = [ enc, pkRm, pkSm ]
        dh = B.append dh1 dh2
     in extractAndExpand kdf (SharedSecret dh) kemContext

groupAuthEncap :: (GroupKEM group, MonadRandom r)
               => proxy group -> GroupPublic group -> GroupPrivate group -> GroupPublic group -> r (CryptoFailable Zz, Enc)
groupAuthEncap grp pkR skS pkS = do
    (skE, pkE) <- groupGenerateKeyPair grp
    let mDh1 = groupGetShared grp pkR skE
        mDh2 = groupGetShared grp pkR skS
        enc  = groupSerialize grp pkE
        mZz  = groupAuthCombine grp enc pkR pkS <$> mDh1 <*> mDh2
    return (mZz, enc)

groupAuthDecap :: GroupKEM group
               => proxy group -> Enc -> GroupPrivate group -> GroupPublic group -> GroupPublic group -> CryptoFailable Zz
groupAuthDecap grp enc skR pkR pkS = do
    pkE <- groupDeserialize grp enc
    let mDh1 = groupGetShared grp pkE skR
        mDh2 = groupGetShared grp pkS skR
    groupAuthCombine grp enc pkR pkS <$> mDh1 <*> mDh2

groupKemName :: GroupKEM group => proxy group -> String
groupKemName grp = "DHKEM(" ++ groupName grp ++ ", " ++ kdfName kdf ++ ")"
  where kdf = groupKDF grp

-- | Groups supporting DH-Based KEM.
class GroupKEM group where
    -- | Return the identifier of the KEM for this group.
    groupKemID :: proxy group -> KemID

    -- | Return the name of the group.
    groupName :: proxy group -> String

    -- | Return the KDF to use for DH-Based KEM with this group.
    groupKDF :: proxy group -> KDF

    -- | Type of public keys for the group.
    type GroupPublic group :: Type

    -- | Type of private keys for the group.
    type GroupPrivate group :: Type

    -- | Generate a random key pair.
    groupGenerateKeyPair :: MonadRandom r
                         => proxy group
                         -> r (GroupPrivate group, GroupPublic group)

    -- | Perform a non-interactive DH exchange using the private key @sk@ and
    -- public key @pk@ to produce a Diffie-Hellman shared secret.
    groupGetShared :: proxy group
                   -> GroupPublic group
                   -> GroupPrivate group
                   -> CryptoFailable SharedSecret

    -- | Produce a fixed-length byte string encoding the public key @pk@.
    groupSerialize :: ByteArray ba
                   => proxy group
                   -> GroupPublic group
                   -> ba

    -- | Parse a fixed-length byte string to recover a public key.
    groupDeserialize :: ByteArray ba
                     => proxy group
                     -> ba
                     -> CryptoFailable (GroupPublic group)

-- | Groups supporting DH-Based KEM with static keys.
class GroupKEM group => GroupStaticKEM group where
    -- | Produce a fixed-length byte string encoding the private key @sk@.
    groupSerializePrivate :: ByteArray ba
                          => proxy group
                          -> GroupPrivate group
                          -> ba

    -- | Parse a fixed-length byte string containing a private key and return
    -- the key pair.
    groupDeserializePrivate :: ByteArray ba
                            => proxy group
                            -> ba
                            -> CryptoFailable (GroupPrivate group, GroupPublic group)

-- | Groups supporting DH-Based KEM with key derivation.
class GroupKEM group => GroupDeriveKEM group where
    -- | Derive a key pair from the byte string @ikm@.
    groupDeriveKeyPair :: ByteArrayAccess ikm
                       => proxy group
                       -> ikm
                       -> (GroupPrivate group, GroupPublic group)

instance GroupKEM group => KEM (DHKEM group) where
    kemID = groupKemID . unDHKEM

    type KEMPublic (DHKEM group) = GroupPublic group
    type KEMPrivate (DHKEM group) = GroupPrivate group

    kemName = groupKemName . unDHKEM

    generateKeyPair = groupGenerateKeyPair . unDHKEM

    encap = groupEncap . unDHKEM
    decap = groupDecap . unDHKEM

    serialize = groupSerialize . unDHKEM
    deserialize = groupDeserialize . unDHKEM

instance GroupKEM group => AuthKEM (DHKEM group) where
    authEncap = groupAuthEncap . unDHKEM
    authDecap = groupAuthDecap . unDHKEM

instance GroupStaticKEM group => StaticKEM (DHKEM group) where
    serializePrivate = groupSerializePrivate . unDHKEM
    deserializePrivate = groupDeserializePrivate . unDHKEM

instance GroupDeriveKEM group => DeriveKEM (DHKEM group) where
    deriveKeyPair = groupDeriveKeyPair . unDHKEM
