-- |
-- Module      : Crypto.PubKey.HPKE
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Hybrid Public Key Encryption (HPKE), defined in
-- <https://tools.ietf.org/html/draft-irtf-cfrg-hpke draft-irtf-cfrg-hpke>.
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
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}
module Crypto.PubKey.HPKE
    (
    -- * Creating an HPKE context
      Context
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
    , export
    -- * Algorithms and definitions
    -- ** KEM
    , KemID
    , Zz
    , Enc
    , KEM(..)
    , AuthKEM(..)
    , StaticKEM(..)
    , DHKEM
    , GroupKEM
    , GroupStaticKEM
    , ECGroup
    , EllipticCurveGroup
    , EllipticCurveStaticGroup
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
import Crypto.PubKey.HPKE.DHKEM
import Crypto.PubKey.HPKE.EC
import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.KEM
import Crypto.PubKey.HPKE.Label
import Crypto.PubKey.HPKE.Imports


{- Setup -}

-- | HPKE context
data Context = Context
    { ctxEncrypt  :: forall aad ba a . (ByteArrayAccess aad, ByteArray ba) => (RunAEAD aad ba -> a) -> a
    , ctxDecrypt  :: forall aad ba a . (ByteArrayAccess aad, ByteArray ba) => (RunAEAD aad ba -> a) -> a
    , ctxTagLen   :: Int
    , ctxNonce    :: NonceAEAD
    , ctxExport   :: forall out . ByteArray out => ByteString -> Int -> out
    , ctxSeq      :: NonceAEAD
    }

pskNone :: Maybe (Bytes, Bytes)
pskNone = Nothing

keySchedule :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
            => proxy kem
            -> Cipher
            -> ScrubbedBytes
            -> info
            -> Maybe (psk, pskId)
            -> Bool
            -> CryptoFailable Context
keySchedule kem cipher zz info mPskInfo bPkS = do
    let kemId  = kemID kem
        kdfId  = kdfID kdf
        aeadId = aeadID aead

        default_psk   = B.zero nh
        default_pskID = B.empty

        psk   = maybe default_psk fst mPskInfo
        pskID = maybe default_pskID snd mPskInfo

        pskID_hash = withKDF kdf (labeledExtract "pskID_hash" pskID) B.convert
        info_hash  = withKDF kdf (labeledExtract "info_hash" info) B.convert
        csuite     = be16 kemId . be16 kdfId . be16 aeadId
        context    = csuite [ B.singleton mode, pskID_hash, info_hash ]

        withPSK    = withKDF kdf $ labeledExtract "psk_hash" psk
        withSecret = withKDF kdf $ withPSK $ \psk_hash ->
            labeledExtractSalt psk_hash "secret" zz

        key        = withSecret $ \s -> labeledExpand s "key" context nk
        nonce      = withSecret $ \s -> labeledExpand s "nonce" context nn
        exporter   = withSecret $ \s -> labeledExpand s "exp" context nh

        exportF :: ByteArray out => ByteString -> Int -> out
        exportF = withKDF kdf (extractSkip (exporter :: Bytes)) $ \s ->
            labeledExpand s "sec" . (:[])

    return Context { ctxEncrypt  = \f -> f (aeadEncryptF aead key)
                   , ctxDecrypt  = \f -> f (aeadDecryptF aead key)
                   , ctxTagLen   = aeadAuthTagLen aead
                   , ctxNonce    = nonce
                   , ctxExport   = exportF
                   , ctxSeq      = B.zero nn
                   }
  where
    mode = (if isJust mPskInfo then 1 else 0) + (if bPkS then 2 else 0)

    kdf  = cipherKDF cipher
    nh   = kdfNh kdf
    aead = cipherAEAD cipher
    nk   = aeadNk aead
    nn   = aeadNn aead

-- | Encryption to a public key.
setupBaseS :: (KEM kem, ByteArrayAccess info, MonadRandom r)
           => proxy kem
           -> Cipher
           -> KEMPublic kem
           -> info
           -> r (CryptoFailable (Enc, Context))
setupBaseS kem cipher pkR info = do
    (mZz, enc) <- encap kem pkR
    return $ do
        zz <- mZz
        ctx <- keySchedule kem cipher zz info pskNone False
        return (enc, ctx)

-- | Decryption with a private key.
setupBaseR :: (KEM kem, ByteArrayAccess info)
           => proxy kem
           -> Cipher
           -> Enc
           -> (KEMPrivate kem, KEMPublic kem)
           -> info
           -> CryptoFailable Context
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
          -> r (CryptoFailable (Enc, Context))
setupPSKS kem cipher pkR info psk pskId = do
    (mZz, enc) <- encap kem pkR
    return $ do
        zz <- mZz
        ctx <- keySchedule kem cipher zz info (Just (psk, pskId)) False
        return (enc, ctx)

-- | Decryption with a private key using Pre-Shared Key authentication.
setupPSKR :: (KEM kem, ByteArrayAccess info, ByteArray psk, ByteArray pskId)
          => proxy kem
          -> Cipher
          -> Enc
          -> (KEMPrivate kem, KEMPublic kem)
          -> info
          -> psk -> pskId
          -> CryptoFailable Context
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
           -> r (CryptoFailable (Enc, Context))
setupAuthS kem cipher pkR info (skS, pkS) = do
    (mZz, enc) <- authEncap kem pkR skS pkS
    return $ do
        zz <- mZz
        ctx <- keySchedule kem cipher zz info pskNone True
        return (enc, ctx)

-- | Decryption with a private key using Asymmetric Key authentication.
setupAuthR :: (AuthKEM kem, ByteArrayAccess info)
           => proxy kem
           -> Cipher
           -> Enc
           -> (KEMPrivate kem, KEMPublic kem)
           -> info
           -> KEMPublic kem
           -> CryptoFailable Context
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
              -> r (CryptoFailable (Enc, Context))
setupAuthPSKS kem cipher pkR info psk pskId (skS, pkS) = do
    (mZz, enc) <- authEncap kem pkR skS pkS
    return $ do
        zz <- mZz
        ctx <- keySchedule kem cipher zz info (Just (psk, pskId)) True
        return (enc, ctx)

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
              -> CryptoFailable Context
setupAuthPSKR kem cipher enc (skR, pkR) info psk pskId pkS = do
    zz <- authDecap kem enc skR pkR pkS
    keySchedule kem cipher zz info (Just (psk, pskId)) True


{- AEAD -}

-- | Return the length in bytes added to sealed content.
tagLength :: Context -> Int
tagLength = ctxTagLen

nextNonce :: Context -> (NonceAEAD, Context)
nextNonce ctx =
    let nextSeq = fromJust "HPKE nonce overflow" $ incbe (ctxSeq ctx)
     in (ctxSeq ctx `B.xor` ctxNonce ctx, ctx { ctxSeq = nextSeq })

-- | Encrypt and authenticate plaintext @pt@ with associated data @aad@ and
-- using the HPKE context.  Returns a new context to be used for the next
-- encryption.
seal :: (ByteArrayAccess aad, ByteArray ba)
     => Context -> aad -> ba -> (ba, Context)
seal ctx aad pt =
    ctxEncrypt ctx $ \encryptF ->
        let (e, AuthTag authtag) = encryptF nonce pt aad
         in (e `B.append` B.convert authtag, nextCtx)
  where
    (nonce, nextCtx) = nextNonce ctx

-- | Decrypt ciphertext @ct@ with associated data @aad@ and using the HPKE
-- context.  Returns a new context to be used for the next decryption.
open :: (ByteArrayAccess aad, ByteArray ba)
     => Context -> aad -> ba -> (Maybe ba, Context)
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

incbe :: NonceAEAD -> Maybe NonceAEAD
incbe bs =
    case go 1 (B.unpack bs) of
        (0, newBytes) -> Just (B.pack newBytes)
        _             -> Nothing
  where
    go a []     = (a, [])
    go a (i:is) = let { (b, os) = go a is; (c, o) = b `add` i } in (c, o:os)

    add x y = let d = promote x + promote y in (demote $ d `shiftR` 8, demote d)

    promote = fromIntegral :: Word8 -> Word16
    demote  = fromIntegral :: Word16 -> Word8


{- Secret Export -}

-- | Produce a secret derived from the internal exporter secret, specifying a
-- context string and the desired length in bytes.
export :: ByteArray out => Context -> ByteString -> Int -> out
export = ctxExport
