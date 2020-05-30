-- |
-- Module      : Crypto.PubKey.HPKE.KEM
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.PubKey.HPKE.KEM
    ( KemID
    , Zz
    , Enc
    , KEM(..)
    , AuthKEM(..)
    , StaticKEM(..)
    ) where

import Data.Kind (Type)

import Crypto.Error
import Crypto.Random

import Crypto.PubKey.HPKE.Imports

-- | Key Encapsulation Mechanism (KEM) identifier.
type KemID = Word16

-- | Symmetric key generated by the KEM.
type Zz = ScrubbedBytes

-- | Encapsulated key generated by the KEM.
type Enc = ByteString

-- | A Key Encapsulation Mechanism (KEM).
class KEM kem where
    -- | Return the identifier of the KEM.
    kemID :: proxy kem -> KemID

    -- | Type of public keys for the KEM.
    type KEMPublic kem :: Type

    -- | Type of private keys for the KEM.
    type KEMPrivate kem :: Type

    -- | Return the name of the KEM.
    kemName :: proxy kem -> String

    -- | Generate a random key pair.
    generateKeyPair :: MonadRandom r
                    => proxy kem
                    -> r (KEMPrivate kem, KEMPublic kem)

    -- | Generate an ephemeral, fixed-length symmetric key and a fixed-length
    -- encapsulation of that key that can be decapsulated by the holder of the
    -- private key corresponding to @pkR@.
    encap :: MonadRandom r
          => proxy kem
          -> KEMPublic kem
          -> r (CryptoFailable Zz, Enc)

    -- | Use the private key @skR@ to recover the ephemeral symmetric key from
    -- its encapsulated representation @enc@.
    decap :: proxy kem
          -> Enc
          -> KEMPrivate kem
          -> KEMPublic kem
          -> CryptoFailable Zz

    -- | Produce a fixed-length octet string encoding the public key @pk@.
    marshal :: ByteArray ba
            => proxy kem
            -> KEMPublic kem
            -> ba

    -- | Parse a fixed-length octet string to recover a public key.
    unmarshal :: ByteArray ba
              => proxy kem
              -> ba
              -> CryptoFailable (KEMPublic kem)

-- | A KEM supporting Asymmetric Key authentication.
class KEM kem => AuthKEM kem where

    -- | Same as 'encap', but the outputs encode an assurance that the KEM
    -- shared secret key is known only to the holder of the private key @skS@.
    authEncap :: MonadRandom r
              => proxy kem
              -> KEMPublic kem
              -> KEMPrivate kem
              -> KEMPublic kem
              -> r (CryptoFailable Zz, Enc)

    -- | Same as 'decap', but the holder of the private key @skR@ is assured
    -- that the KEM shared secret key is known only to the holder of the private
    -- key corresponding to @pkS@.
    authDecap :: proxy kem
              -> Enc
              -> KEMPrivate kem
              -> KEMPublic kem
              -> KEMPublic kem
              -> CryptoFailable Zz

-- | A KEM supporting static keys.
class KEM kem => StaticKEM kem where

    -- | Produce a fixed-length octet string encoding the private key @sk@.
    marshalPrivate :: ByteArray ba
                   => proxy kem
                   -> KEMPrivate kem
                   -> ba

    -- | Parse a fixed-length octet string containing a private key and return
    -- the key pair.
    unmarshalPrivate :: ByteArray ba
                     => proxy kem
                     -> ba
                     -> CryptoFailable (KEMPrivate kem, KEMPublic kem)
