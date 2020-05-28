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
    , EllipticCurveGroup
    ) where

import qualified Data.ByteArray as B

import           Crypto.ECC
import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import           Crypto.PubKey.ECIES
import qualified Crypto.PubKey.ECC.P256 as P256
import           Crypto.Random

import Crypto.PubKey.HPKE.Cipher
import Crypto.PubKey.HPKE.DHKEM
import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.KEM
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

    -- | Produce a fixed-length octet string encoding the private key @sk@.
    ecMarshalPrivate :: ByteArray ba
                     => proxy curve
                     -> Scalar curve
                     -> ba

    -- | Parse a fixed-length octet string containing a private key and return
    -- the key pair.
    ecUnmarshalPrivate :: ByteArray ba
                       => proxy curve
                       -> ba
                       -> CryptoFailable (Scalar curve, Point curve)

    -- | Perform a non-interactive DH exchange using the private key @sk@ and
    -- public key @pk@ to produce a Diffie-Hellman shared secret.
    ecGetShared :: proxy curve
                -> Point curve
                -> Scalar curve
                -> CryptoFailable SharedSecret

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

    groupMarshalPrivate = ecMarshalPrivate . unECGroup
    groupUnmarshalPrivate = ecUnmarshalPrivate . unECGroup

    groupGenerateKeyPair = ecGenerateKeyPair . unECGroup

    groupGetShared = ecGetShared . unECGroup

    groupMarshal = encodePoint . unECGroup
    groupUnmarshal = decodePoint . unECGroup

instance EllipticCurveGroup Curve_P256R1 where
    ecKemID _ = 0x0010
    ecName _  = "P-256"
    ecKDF _   = hkdf_sha256

    ecMarshalPrivate _ = P256.scalarToBinary
    ecUnmarshalPrivate _ bs = build <$> P256.scalarFromBinary bs
      where build k = (k, P256.toPoint k)

    ecGetShared = deriveDecryptHpke

instance EllipticCurveGroup Curve_X25519 where
    ecKemID _ = 0x0020
    ecName _  = "X25519"
    ecKDF _   = hkdf_sha256

    ecMarshalPrivate _ = B.convert
    ecUnmarshalPrivate _ bs = build <$> X25519.secretKey bs
      where build k = (k, X25519.toPublic k)

    ecGetShared = deriveDecrypt

instance EllipticCurveGroup Curve_X448 where
    ecKemID _ = 0x0021
    ecName _  = "X448"
    ecKDF _   = hkdf_sha512

    ecMarshalPrivate _ = B.convert
    ecUnmarshalPrivate _ bs = build <$> X448.secretKey bs
      where build k = (k, X448.toPublic k)

    ecGetShared = deriveDecrypt

-- Variant of deriveDecrypt for NIST curves: the shared secret is the
-- uncompressed encoding of the resulting point, not just the X coordinate.
deriveDecryptHpke :: (EllipticCurveDH curve, EllipticCurveArith curve)
                  => proxy curve
                  -> Point curve
                  -> Scalar curve
                  -> CryptoFailable SharedSecret
deriveDecryptHpke prx p s = do
    _ <- deriveDecrypt prx p s  -- just for validation
    return $ SharedSecret $ encodePoint prx $ pointSmul prx s p
