-- |
-- Module      : Crypto.PubKey.HPKE
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Hybrid Public Key Encryption (HPKE), defined in
-- <https://datatracker.ietf.org/doc/html/rfc9180 RFC 9180>.
--
-- HPKE schemes combine asymmetric and symmetric algorithms in an interoperable
-- standard to secure communications between a sender (S) and a recipient (R).
--
-- The sender prepares an encryption context @ctx@ by selecting a 'KEM', a 'KDF'
-- and an 'AEAD' encryption algorithm.  In base mode, the context then just
-- needs the public key of the recipient @pkR@, and optional app-specific
-- information @info@ that influences symmetric encryption keys.  Context setup
-- with 'setupBaseS' generates a random ephemeral key, and the corresponding
-- encapsulated key @enc@ is returned along with the HPKE context:
--
-- @
-- CryptoPassed (enc, ctx) <- 'setupBaseS' kem cipher pkR info
-- @
--
-- When in possession of the encapsulated key @enc@, the recipient calls
-- 'setupBaseR' to create an equivalent HPKE context with its key pair @(skR,
-- pkR)@, and the same algorithm parameters that the sender used:
--
-- @
-- let CryptoPassed ctx = 'setupBaseR' kem cipher enc (skR, pkR) info
-- @
--
-- The sender and recipient can then perform one or more AEAD operations 'seal'
-- and 'open', all bound cryptographically to the context.  The HPKE context
-- maintains an internal sequence number to generate appropriate nonces.
-- Consecutive sender and recipient operations must be performed in same order
-- on both sides.  From the HPKE context it is also possible to derive arbitrary
-- secrets with the 'export' function.
--
-- The base mode is similar to epheremal-static Diffie-Hellman and just needs
-- the asymmetric key of the recipient.  Other HPKE modes bring additional
-- authentication with Pre-Shared Key, or sender asymmetric key, or both. Sender
-- setup is replaced with functions 'setupPSKS', 'setupAuthS' or
-- 'setupAuthPSKS'.  Recipient setup uses instead functions 'setupPSKR',
-- 'setupAuthR', or 'setupAuthPSKR'.
--
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}
module Crypto.PubKey.HPKE
    (
    -- * Creating an HPKE context
      Context
    , Role(..)
    , Cipher(..)
    -- ** Encryption to a Public Key
    , setupBaseS
    , setupBaseR
    -- ** Authentication using a Pre-Shared Key
    , setupPSKS
    , setupPSKR
    -- ** Authentication using an Asymmetric Key
    , setupAuthS
    , setupAuthR
    -- ** Authentication using both a PSK and an Asymmetric Key
    , setupAuthPSKS
    , setupAuthPSKR
    -- * Using an HPKE context
    , tagLength
    , seal
    , open
    , skip
    , export
    -- * Algorithms and definitions
    -- ** KEM
    , KemID
    , Zz
    , Enc
    , KEM(..)
    , AuthKEM(..)
    , StaticKEM(..)
    , DeriveKEM(..)
    , DHKEM
    , GroupKEM
    , GroupStaticKEM
    , GroupDeriveKEM
    , ECGroup
    , EllipticCurveGroup
    , EllipticCurveStaticGroup
    , EllipticCurveDeriveGroup
    -- ** KDF
    , KdfID
    , KDF
    , kdfID
    , kdfName
    , hkdf_sha256
    , hkdf_sha384
    , hkdf_sha512
    -- ** AEAD
    , AeadID
    , AEAD
    , aeadID
    , aeadName
    , aead_aes128gcm
    , aead_aes256gcm
    , aead_chacha20poly1305
    ) where

import qualified Data.ByteArray as B

import Crypto.Cipher.Types (AuthTag(..))
import Crypto.Error
import Crypto.KDF.HKDF
import Crypto.Random

import Crypto.PubKey.HPKE.AEAD
import Crypto.PubKey.HPKE.Cipher
import Crypto.PubKey.HPKE.Context
import Crypto.PubKey.HPKE.DHKEM
import Crypto.PubKey.HPKE.EC
import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.KEM
import Crypto.PubKey.HPKE.Label
import Crypto.PubKey.HPKE.Imports


{- Setup -}

pskNone :: Maybe (Bytes, Bytes)
pskNone = Nothing

keySchedule :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
            => proxy kem
            -> Cipher
            -> ScrubbedBytes
            -> info
            -> Maybe (psk, pskId)
            -> Bool
            -> CryptoFailable (Context r)
keySchedule kem cipher zz info mPskInfo bPkS = do
    let kemId  = kemID kem
        kdfId  = kdfID kdf
        aeadId = aeadID aead

        default_psk   = B.empty
        default_pskID = B.empty

        psk   = maybe default_psk fst mPskInfo
        pskID = maybe default_pskID snd mPskInfo

        pskID_hash = withKDF kdf (labeledExtract sid "psk_id_hash" pskID) B.convert
        info_hash  = withKDF kdf (labeledExtract sid "info_hash" info) B.convert
        csuite     = be16 kemId . be16 kdfId . be16 aeadId
        sid        = ("HPKE" :) . csuite
        context    = [ B.singleton mode, pskID_hash, info_hash ]

        withSecret = withKDF kdf $ labeledExtractSalt zz sid "secret" psk

        key        = withSecret $ \s -> labeledExpand s sid "key" context nk
        base_nonce = withSecret $ \s -> labeledExpand s sid "base_nonce" context nn
        exporter   = withSecret $ \s -> labeledExpand s sid "exp" context nh

        exportF :: ByteArray out => ByteString -> Int -> out
        exportF = withKDF kdf (extractSkip (exporter :: Bytes)) $ \s ->
            labeledExpand s sid "sec" . (:[])

    return Context { ctxEncrypt   = \f -> f (aeadEncryptF aead key)
                   , ctxDecrypt   = \f -> f (aeadDecryptF aead key)
                   , ctxTagLen    = aeadAuthTagLen aead
                   , ctxBaseNonce = base_nonce
                   , ctxExport    = exportF
                   , ctxSeq       = B.zero nn
                   }
  where
    mode = (if isJust mPskInfo then 1 else 0) + (if bPkS then 2 else 0)

    kdf  = cipherKDF cipher
    nh   = kdfNh kdf
    aead = cipherAEAD cipher
    nk   = aeadNk aead
    nn   = aeadNn aead

keyScheduleS :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
             => proxy kem
             -> Cipher
             -> (CryptoFailable Zz, Enc)
             -> info
             -> Maybe (psk, pskId)
             -> Bool
             -> CryptoFailable (Enc, Context r)
keyScheduleS kem cipher (mZz, enc) info mPskInfo bPkS = do
    zz <- mZz
    ctx <- keySchedule kem cipher zz info mPskInfo bPkS
    return (enc, ctx)

-- | Encryption to a public key.
setupBaseS :: (KEM kem, ByteArrayAccess info, MonadRandom r)
           => proxy kem
           -> Cipher
           -> KEMPublic kem
           -> info
           -> r (CryptoFailable (Enc, Context 'Sender))
setupBaseS kem cipher pkR info = do
    r <- encap kem pkR
    return $ keyScheduleS kem cipher r info pskNone False

-- | Decryption with a private key.
setupBaseR :: (KEM kem, ByteArrayAccess info)
           => proxy kem
           -> Cipher
           -> Enc
           -> (KEMPrivate kem, KEMPublic kem)
           -> info
           -> CryptoFailable (Context 'Recipient)
setupBaseR kem cipher enc (skR, pkR) info = do
    zz <- decap kem enc skR pkR
    keySchedule kem cipher zz info pskNone False

-- | Encryption to a public key using Pre-Shared Key authentication.
setupPSKS :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId, MonadRandom r)
          => proxy kem
          -> Cipher
          -> KEMPublic kem
          -> info
          -> psk -> pskId
          -> r (CryptoFailable (Enc, Context 'Sender))
setupPSKS kem cipher pkR info psk pskId = do
    r <- encap kem pkR
    return $ keyScheduleS kem cipher r info (Just (psk, pskId)) False

-- | Decryption with a private key using Pre-Shared Key authentication.
setupPSKR :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
          => proxy kem
          -> Cipher
          -> Enc
          -> (KEMPrivate kem, KEMPublic kem)
          -> info
          -> psk -> pskId
          -> CryptoFailable (Context 'Recipient)
setupPSKR kem cipher enc (skR, pkR) info psk pskId = do
    zz <- decap kem enc skR pkR
    keySchedule kem cipher zz info (Just (psk, pskId)) False

-- | Encryption to a public key using Asymmetric Key authentication.
setupAuthS :: (AuthKEM kem, ByteArrayAccess info, MonadRandom r)
           => proxy kem
           -> Cipher
           -> KEMPublic kem
           -> info
           -> (KEMPrivate kem, KEMPublic kem)
           -> r (CryptoFailable (Enc, Context 'Sender))
setupAuthS kem cipher pkR info (skS, pkS) = do
    r <- authEncap kem pkR skS pkS
    return $ keyScheduleS kem cipher r info pskNone True

-- | Decryption with a private key using Asymmetric Key authentication.
setupAuthR :: (AuthKEM kem, ByteArrayAccess info)
           => proxy kem
           -> Cipher
           -> Enc
           -> (KEMPrivate kem, KEMPublic kem)
           -> info
           -> KEMPublic kem
           -> CryptoFailable (Context 'Recipient)
setupAuthR kem cipher enc (skR, pkR) info pkS = do
    zz <- authDecap kem enc skR pkR pkS
    keySchedule kem cipher zz info pskNone True

-- | Encryption to a public key using authentication with both a PSK and an
-- Asymmetric Key.
setupAuthPSKS :: (AuthKEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId, MonadRandom r)
              => proxy kem
              -> Cipher
              -> KEMPublic kem
              -> info
              -> psk -> pskId
              -> (KEMPrivate kem, KEMPublic kem)
              -> r (CryptoFailable (Enc, Context 'Sender))
setupAuthPSKS kem cipher pkR info psk pskId (skS, pkS) = do
    r <- authEncap kem pkR skS pkS
    return $ keyScheduleS kem cipher r info (Just (psk, pskId)) True

-- | Decryption with a private key using authentication with both a PSK and an
-- Asymmetric Key.
setupAuthPSKR :: (AuthKEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
              => proxy kem
              -> Cipher
              -> Enc
              -> (KEMPrivate kem, KEMPublic kem)
              -> info
              -> psk -> pskId
              -> KEMPublic kem
              -> CryptoFailable (Context 'Recipient)
setupAuthPSKR kem cipher enc (skR, pkR) info psk pskId pkS = do
    zz <- authDecap kem enc skR pkR pkS
    keySchedule kem cipher zz info (Just (psk, pskId)) True


{- AEAD -}

-- | Return the length in bytes added to sealed content.
tagLength :: Context r -> Int
tagLength = ctxTagLen

-- | Encrypt and authenticate plaintext @pt@ with associated data @aad@ and
-- using the HPKE context.  Returns a new context to be used for the next
-- encryption.
seal :: (ByteArrayAccess aad, ByteArray ba)
     => Context 'Sender -> aad -> ba -> (ba, Context 'Sender)
seal ctx aad pt =
    ctxEncrypt ctx $ \encryptF ->
        let (e, AuthTag authtag) = encryptF nonce pt aad
         in (e `B.append` B.convert authtag, nextCtx)
  where
    (nonce, nextCtx) = nextNonce ctx

-- | Decrypt ciphertext @ct@ with associated data @aad@ and using the HPKE
-- context.  Returns a new context to be used for the next decryption.
open :: (ByteArrayAccess aad, ByteArray ba)
     => Context 'Recipient -> aad -> ba -> (Maybe ba, Context 'Recipient)
open ctx aad ct = (, nextCtx) <$>
    ctxDecrypt ctx $ \decryptF -> do
        guard (plainLen >= 0)
        let (e, authtag) = B.splitAt plainLen ct
            (pt, AuthTag authtag2) = decryptF nonce e aad
        guard (authtag `B.constEq` authtag2)
        return pt
  where
    (nonce, nextCtx) = nextNonce ctx
    plainLen = B.length ct - ctxTagLen ctx

-- | Increment the nonce counter without doing any AEAD operation.
skip :: Context r -> Context r
skip = snd . nextNonce


{- Secret Export -}

-- | Produce a secret derived from the internal exporter secret, specifying a
-- context string and the desired length in bytes.
{-# ANN export ("HLint: ignore Eta reduce" :: String) #-}
export :: ByteArray out => Context r -> ByteString -> Int -> out
export ctx = ctxExport ctx
