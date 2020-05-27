-- |
-- Module      : Crypto.PubKey.HPKE.Cipher
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
module Crypto.PubKey.HPKE.Cipher
    ( Cipher(..)
    , hkdf_sha256
    , hkdf_sha384
    , hkdf_sha512
    , aead_aes128gcm
    , aead_aes256gcm
    , aead_chacha20poly1305
    ) where

import Crypto.PubKey.HPKE.AEAD
import Crypto.PubKey.HPKE.KDF
import Crypto.PubKey.HPKE.Imports

import Data.Tuple (swap)

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types hiding (AEAD, Cipher, cipherName)
import qualified Crypto.Cipher.Types as Cipher
import Crypto.Error
import Crypto.Hash
import qualified Crypto.MAC.Poly1305 as Poly1305

-- | Hold which KDF and AEAD to use in HPKE.
data Cipher = Cipher
    { cipherKDF       :: KDF   -- ^ The KDF to use
    , cipherAEAD      :: AEAD  -- ^ The AEAD to use
    }

instance Show Cipher where
    show c = kdfName (cipherKDF c) ++ ", " ++ aeadName (cipherAEAD c)

-- | HKDF-SHA256
hkdf_sha256 :: KDF
hkdf_sha256 = KDF
    { kdfID      = 0x0001
    , kdfName    = "HKDF-SHA256"
    , kdfHash    = SHA256
    }

-- | HKDF-SHA384
hkdf_sha384 :: KDF
hkdf_sha384 = KDF
    { kdfID      = 0x0002
    , kdfName    = "HKDF-SHA384"
    , kdfHash    = SHA384
    }

-- | HKDF-SHA512
hkdf_sha512 :: KDF
hkdf_sha512 = KDF
    { kdfID      = 0x0003
    , kdfName    = "HKDF-SHA512"
    , kdfHash    = SHA512
    }

enc_aes128gcm, dec_aes128gcm
    :: (ByteArrayAccess aad, ByteArray ba)
    => KeyAEAD -> RunAEAD aad ba
enc_aes128gcm key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16)
dec_aes128gcm key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in simpleDecrypt aeadIni ad d 16)

enc_aes256gcm, dec_aes256gcm
    :: (ByteArrayAccess aad, ByteArray ba)
    => KeyAEAD -> RunAEAD aad ba
enc_aes256gcm key =
    let ctx = noFail (cipherInit key) :: AES256
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16)
dec_aes256gcm key =
    let ctx = noFail (cipherInit key) :: AES256
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in simpleDecrypt aeadIni ad d 16)

simpleDecrypt :: (ByteArrayAccess aad, ByteArray ba)
              => Cipher.AEAD cipher
              -> aad
              -> ba
              -> Int
              -> (ba, AuthTag)
simpleDecrypt aeadIni header input taglen = (output, tag)
  where
        aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadDecrypt aead input
        tag                 = aeadFinalize aeadFinal taglen

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

enc_chacha20poly1305, dec_chacha20poly1305
    :: (ByteArrayAccess aad, ByteArray ba)
    => KeyAEAD -> RunAEAD aad ba
enc_chacha20poly1305 key nonce =
    let st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)
     in (\input ad ->
            let st2 = ChaChaPoly1305.finalizeAAD (ChaChaPoly1305.appendAAD ad st)
                (output, st3) = ChaChaPoly1305.encrypt input st2
                Poly1305.Auth tag = ChaChaPoly1305.finalize st3
            in (output, AuthTag tag))
dec_chacha20poly1305 key nonce =
    let st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)
     in (\input ad ->
            let st2 = ChaChaPoly1305.finalizeAAD (ChaChaPoly1305.appendAAD ad st)
                (output, st3) = ChaChaPoly1305.decrypt input st2
                Poly1305.Auth tag = ChaChaPoly1305.finalize st3
            in (output, AuthTag tag))

-- | AES-GCM-128
aead_aes128gcm :: AEAD
aead_aes128gcm = AEAD
    { aeadID           = 0x0001
    , aeadName         = "AES-GCM-128"
    , aeadNk           = 16
    , aeadNn           = 12
    , aeadAuthTagLen   = 16
    , aeadEncryptF     = enc_aes128gcm
    , aeadDecryptF     = dec_aes128gcm
    }

-- | AES-GCM-256
aead_aes256gcm :: AEAD
aead_aes256gcm = AEAD
    { aeadID           = 0x0002
    , aeadName         = "AES-GCM-256"
    , aeadNk           = 32
    , aeadNn           = 12
    , aeadAuthTagLen   = 16
    , aeadEncryptF     = enc_aes256gcm
    , aeadDecryptF     = dec_aes256gcm
    }

-- | ChaCha20Poly1305
aead_chacha20poly1305 :: AEAD
aead_chacha20poly1305 = AEAD
    { aeadID           = 0x0003
    , aeadName         = "ChaCha20Poly1305"
    , aeadNk           = 32
    , aeadNn           = 12
    , aeadAuthTagLen   = 16
    , aeadEncryptF     = enc_chacha20poly1305
    , aeadDecryptF     = dec_chacha20poly1305
    }
