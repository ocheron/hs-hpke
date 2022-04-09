-- |
-- Module      : Crypto.PubKey.HPKE.EC
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.PubKey.HPKE.EC
    ( ECGroup
    , EllipticCurveGroup(..)
    , EllipticCurveStaticGroup(..)
    , EllipticCurveDeriveGroup(..)
    ) where

import qualified Data.ByteArray as B

import           Crypto.ECC
import           Crypto.Error
import           Crypto.Hash
import           Crypto.KDF.HKDF
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import           Crypto.PubKey.ECIES
import qualified Crypto.PubKey.ECC.P256 as P256
import           Crypto.Random

import Crypto.PubKey.HPKE.Cipher
import Crypto.PubKey.HPKE.DHKEM
import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.KEM
import Crypto.PubKey.HPKE.Label
import Crypto.PubKey.HPKE.Imports

import Data.Proxy

ecGenerateKeyPair :: (EllipticCurve curve, MonadRandom r)
                  => proxy curve -> r (Scalar curve, Point curve)
ecGenerateKeyPair prx =
    let unwrap pair = (keypairGetPrivate pair, keypairGetPublic pair)
     in unwrap <$> curveGenerateKeyPair prx

-- | Elliptic curves to be used as a group for DHKEM.
class EllipticCurve curve => EllipticCurveGroup curve where
    -- | Return the identifier of the KEM for this curve.
    ecKemID :: proxy curve -> KemID

    -- | Return the name of the curve.
    ecName :: proxy curve -> String

    -- | Return the KDF to use for DH-Based KEM with this curve.
    ecKDF :: proxy curve -> KDF

    -- | Perform a non-interactive DH exchange using the private key @sk@ and
    -- public key @pk@ to produce a Diffie-Hellman shared secret.
    ecGetShared :: proxy curve
                -> Point curve
                -> Scalar curve
                -> CryptoFailable SharedSecret

-- | Elliptic curves to be used as a group for DHKEM and supporting static keys.
class EllipticCurveGroup curve => EllipticCurveStaticGroup curve where
    -- | Produce a fixed-length byte string encoding the private key @sk@.
    ecSerializePrivate :: ByteArray ba
                       => proxy curve
                       -> Scalar curve
                       -> ba

    -- | Parse a fixed-length byte string containing a private key and return
    -- the key pair.
    ecDeserializePrivate :: ByteArray ba
                         => proxy curve
                         -> ba
                         -> CryptoFailable (Scalar curve, Point curve)

-- | Elliptic curves to be used as a group for DHKEM and supporting key
-- derivation.
class EllipticCurveGroup curve => EllipticCurveDeriveGroup curve where
    -- | Derive a key pair from the byte string @ikm@.
    ecDeriveKeyPair :: ByteArrayAccess ikm
                    => proxy curve
                    -> ikm
                    -> (Scalar curve, Point curve)

-- | An elliptic curve as a Diffie-Hellman group.
data ECGroup curve

unECGroup :: proxy (ECGroup curve) -> Proxy curve
unECGroup _ = Proxy

instance EllipticCurveGroup curve => GroupKEM (ECGroup curve) where
    groupKemID = ecKemID . unECGroup
    groupName = ecName . unECGroup
    groupKDF = ecKDF . unECGroup

    type GroupPublic (ECGroup curve) = Point curve
    type GroupPrivate (ECGroup curve) = Scalar curve

    groupGenerateKeyPair = ecGenerateKeyPair . unECGroup

    groupGetShared = ecGetShared . unECGroup

    groupSerializePublic = encodePoint . unECGroup
    groupDeserializePublic = decodePoint . unECGroup

instance EllipticCurveStaticGroup curve => GroupStaticKEM (ECGroup curve) where
    groupSerializePrivate = ecSerializePrivate . unECGroup
    groupDeserializePrivate = ecDeserializePrivate . unECGroup

instance EllipticCurveDeriveGroup curve => GroupDeriveKEM (ECGroup curve) where
    groupDeriveKeyPair = ecDeriveKeyPair . unECGroup

instance EllipticCurveGroup Curve_P256R1 where
    ecKemID _ = 0x0010
    ecName _  = "P-256"
    ecKDF _   = hkdf_sha256

    ecGetShared = deriveDecrypt

instance EllipticCurveStaticGroup Curve_P256R1 where
    ecSerializePrivate _ = P256.scalarToBinary
    ecDeserializePrivate _ bs = build <$> P256.scalarFromBinary bs
      where build k = (k, P256.toPoint k)

instance EllipticCurveDeriveGroup Curve_P256R1 where
    ecDeriveKeyPair prx = pDeriveKeyPair prx 32

instance EllipticCurveGroup Curve_P384R1 where
    ecKemID _ = 0x0011
    ecName _  = "P-384"
    ecKDF _   = hkdf_sha384

    ecGetShared = deriveDecrypt

instance EllipticCurveGroup Curve_P521R1 where
    ecKemID _ = 0x0012
    ecName _  = "P-521"
    ecKDF _   = hkdf_sha512

    ecGetShared = deriveDecrypt

instance EllipticCurveGroup Curve_X25519 where
    ecKemID _ = 0x0020
    ecName _  = "X25519"
    ecKDF _   = hkdf_sha256

    ecGetShared = deriveDecrypt

instance EllipticCurveStaticGroup Curve_X25519 where
    ecSerializePrivate _ = B.convert
    ecDeserializePrivate _ bs = build <$> X25519.secretKey bs
      where build k = (k, X25519.toPublic k)

instance EllipticCurveDeriveGroup Curve_X25519 where
    ecDeriveKeyPair prx = xDeriveKeyPair prx 32

instance EllipticCurveGroup Curve_X448 where
    ecKemID _ = 0x0021
    ecName _  = "X448"
    ecKDF _   = hkdf_sha512

    ecGetShared = deriveDecrypt

instance EllipticCurveStaticGroup Curve_X448 where
    ecSerializePrivate _ = B.convert
    ecDeserializePrivate _ bs = build <$> X448.secretKey bs
      where build k = (k, X448.toPublic k)

instance EllipticCurveDeriveGroup Curve_X448 where
    ecDeriveKeyPair prx = xDeriveKeyPair prx 56

xDeriveKeyPair :: (EllipticCurveStaticGroup curve, ByteArrayAccess ikm)
               => proxy curve
               -> Int
               -> ikm
               -> (Scalar curve, Point curve)
xDeriveKeyPair prx nsk ikm =
    withKDF (ecKDF prx) (labeledExtract sid "dkp_prk" ikm) $ \prk ->
        build prx (labeledExpand prk sid "sk" [] nsk)
  where
    kemId = ecKemID prx
    sid   = ("KEM" :) . be16 kemId

    build :: EllipticCurveStaticGroup curve
          => proxy curve -> ScrubbedBytes -> (Scalar curve, Point curve)
    build c = throwCryptoError . ecDeserializePrivate c

pDeriveKeyPair :: (EllipticCurveScalarRange curve, ByteArrayAccess ikm)
               => proxy curve
               -> Int
               -> ikm
               -> (Scalar curve, Point curve)
pDeriveKeyPair prx' nsk ikm =
    withKDF (ecKDF prx') (labeledExtract sid "dkp_prk" ikm) (go prx' 0)
  where
    kemId = ecKemID prx'
    sid   = ("KEM" :) . be16 kemId

    go :: (EllipticCurveScalarRange curve, HashAlgorithm hash)
       => proxy curve -> Word8 -> PRK hash -> (Scalar curve, Point curve)
    go prx cnt prk
        | scalarIsInRange prx (fst pair) = pair
        | otherwise = go prx (succ cnt) prk
      where
        infos = [ B.singleton cnt ]
        bytes = labeledExpand prk sid "candidate" infos nsk :: ScrubbedBytes
        pair  = throwCryptoError (ecDeserializePrivate prx bytes)

class EllipticCurveStaticGroup curve => EllipticCurveScalarRange curve where
    scalarIsInRange :: proxy curve -> Scalar curve -> Bool

instance EllipticCurveScalarRange Curve_P256R1 where
    scalarIsInRange _ s =
        not (P256.scalarIsZero s) && P256.scalarCmp s P256.scalarN == LT
