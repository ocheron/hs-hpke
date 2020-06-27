{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main (main) where

import qualified Data.ByteString as B
import Data.List (find)
import Data.Proxy

import Crypto.ECC
import Crypto.Error

import Crypto.PubKey.HPKE as HPKE
import Crypto.PubKey.HPKE.Internal (changeRole)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Utils
import Vectors

instance Show (HPKE.Context r) where
    show _ = "hpke-context"

data SomeKEM = forall kem . (AuthKEM kem, Show (KEMPrivate kem), Show (KEMPublic kem)) => SomeKEM (Proxy kem)

instance Arbitrary SomeKEM where
    arbitrary = elements allKems

instance Show SomeKEM where
    show (SomeKEM kem) = kemName kem

data SomeStaticKEM = forall kem . (AuthKEM kem, StaticKEM kem, Show (KEMPrivate kem), Show (KEMPublic kem)) => SomeStaticKEM (Proxy kem)

main :: IO ()
main = defaultMain $ testGroup "hpke"
    [ testCaseSteps "vectors" test_vectors
    , testGroup "key-derivation vectors" $
        map testDerivation derivationVectors
    , testGroup "properties"
        [ testProperty "Base" prop_base
        , testProperty "PSK" prop_psk
        , testProperty "Auth" prop_auth
        , testProperty "AuthPSK" prop_auth_psk
        ]
    ]


{- Test Vectors -}

test_vectors :: (String -> IO ()) -> Assertion
test_vectors step = do
    step "Reading test vectors ..."
    vecs <- readVectors "test/test-vectors.json.gz"
    mapM_ (testVector step) vecs

testVector :: (String -> IO ()) -> Vector -> Assertion
testVector step Vector{..} = do
    let mKem  = findKEM (fromIntegral vecKemID)
        mKdf  = findKDF (fromIntegral vecKdfID)
        mAead = findAEAD (fromIntegral vecAeadID)
    case (mKem, mKdf, mAead) of
        (Just (SomeStaticKEM kem), Just kdf, Just aead) -> do
            let cipher = Cipher kdf aead
                name   = kemName kem ++ ", " ++ kdfName kdf
                                     ++ ", " ++ aeadName aead
            case (vecSkSm, vecPsk, vecPskID) of
                (Just skSm, Just psk, Just pskID) -> testAuthPSK name kem cipher psk pskID skSm
                (Just skSm, Nothing, Nothing)     -> testAuth name kem cipher skSm
                (Nothing, Just psk, Just pskID)   -> testPSK name kem cipher psk pskID
                (Nothing, Nothing, Nothing)       -> testBase name kem cipher
                _                                 -> fail "invalid vector"
        _ -> return ()
  where
    -- In test vectors we use only the recipient context because the @enc@ value
    -- has already been generated.  In property-based testing the recipient
    -- context is tested against a true sender context, both based on a random
    -- ephemeral key.
    testBase name kem cipher = do
        step ("Base: " ++ name)
        pairR <- fromCryptoPassed $ deserializePrivate kem vecSkRm
        ctx <- fromCryptoPassed $ setupBaseR kem cipher vecEnc pairR vecInfo
        testBoth ctx vecExports vecEncryptions
    testPSK name kem cipher psk pskID = do
        step ("PSK: " ++ name)
        pairR <- fromCryptoPassed $ deserializePrivate kem vecSkRm
        ctx <- fromCryptoPassed $ setupPSKR kem cipher vecEnc pairR vecInfo psk pskID
        testBoth ctx vecExports vecEncryptions
    testAuth name kem cipher skSm = do
        step ("Auth: " ++ name)
        (_, pkS) <- fromCryptoPassed $ deserializePrivate kem skSm
        pairR <- fromCryptoPassed $ deserializePrivate kem vecSkRm
        ctx <- fromCryptoPassed $ setupAuthR kem cipher vecEnc pairR vecInfo pkS
        testBoth ctx vecExports vecEncryptions
    testAuthPSK name kem cipher psk pskID skSm = do
        step ("AuthPSK: " ++ name)
        (_, pkS) <- fromCryptoPassed $ deserializePrivate kem skSm
        pairR <- fromCryptoPassed $ deserializePrivate kem vecSkRm
        ctx <- fromCryptoPassed $ setupAuthPSKR kem cipher vecEnc pairR vecInfo psk pskID pkS
        testBoth ctx vecExports vecEncryptions

    testBoth ctx exports encryptions = testExports ctx exports >>
        testEncryptions (changeRole ctx) ctx encryptions

    testEncryptions _ _ [] = return ()
    testEncryptions ctx0s ctx0r (Encryption{..} : xs) = do
        let (ct, ctx1s) = seal ctx0s eAAD ePlaintext
            (pt, ctx1r) = open ctx0r eAAD eCiphertext
            difference  = B.length eCiphertext - B.length ePlaintext
        assertEqual "ciphertext mismatch" eCiphertext ct
        assertEqual "plaintext mismatch" (Just ePlaintext) pt
        assertEqual "tag length mismatch"
            (difference, difference) (tagLength ctx0s, tagLength ctx0r)
        testEncryptions ctx1s ctx1r xs

    testExports ctx = mapM_ $ \Export{..} ->
        assertEqual "export mismatch" (export ctx eContext eLength) eValue


{- Key Derivation -}

data Derivation = forall kem . (StaticKEM kem, DeriveKEM kem) => Derivation
    { derivKem  :: Proxy kem
    , derivIkm  :: B.ByteString
    , derivSkRm :: B.ByteString
    , derivPkRm :: B.ByteString
    }

derivationVectors :: [Derivation]
derivationVectors =
    [ Derivation
        { derivKem  = Proxy :: Proxy (DHKEM (ECGroup Curve_P256R1))
        , derivIkm  = ""
        , derivSkRm = "\xc5\x24\x6e\x15\x54\x30\xb6\xde\xd4\x0c\x82\xaf\x29\x98\xff\x8b\x4b\x1e\x9a\x93\x21\xf7\x8d\x21\x97\x2b\x26\x18\x18\xce\xd9\xec"
        , derivPkRm = "\x04\xc2\x1e\xbf\x2c\x66\x09\x1a\x81\xc8\x43\xa8\xf6\x47\x1f\x71\xfc\x8f\x79\x40\x75\x3b\x1a\xd0\x0e\x98\xa9\xa0\x9c\x7c\x32\x5a\xf5\xe7\x84\x22\x13\x5e\x0b\x90\x8a\x1f\x6c\x8d\x72\xe0\x4d\xcb\x50\xb7\x3a\x43\xf5\x3c\x6d\x34\xa0\x45\x73\xfb\xcf\x94\x00\xfa\xc7"
        }
    , Derivation
        { derivKem  = Proxy :: Proxy (DHKEM (ECGroup Curve_X25519))
        , derivIkm  = ""
        , derivSkRm = "\x5e\x87\xe0\x3d\xf5\x8d\xa4\xee\xf1\x68\x9c\xc6\x46\xcc\x1d\x15\x04\xd5\x65\x86\x9a\xed\x3c\x53\xec\x45\xba\x72\xf8\xdd\x51\x49"
        , derivPkRm = "\x6a\xb8\x1e\xa7\x58\x83\x38\x43\x97\x43\x97\x09\x19\xbe\xdc\x79\xa7\x53\xd3\x87\x76\x4c\x8b\xbb\xa2\x13\xa8\xbd\xcb\x3e\xd7\x0d"
        }
    , Derivation
        { derivKem  = Proxy :: Proxy (DHKEM (ECGroup Curve_X448))
        , derivIkm  = ""
        , derivSkRm = "\x21\x4d\xb0\x2f\x49\x0e\x8c\xdb\x32\xa6\x45\x2b\xe6\xcd\x80\x8f\xc0\x6b\xae\x64\x29\x53\x44\xaa\x20\x51\xba\x2c\x78\xb2\xec\x83\x1d\x95\x06\xb5\x97\x99\xe4\x1d\x9b\xb2\x5e\x2a\xd7\x56\x4f\xbd\x6e\x84\x54\x09\x53\x64\xc2\x48"
        , derivPkRm = "\x32\x59\x53\x80\xe3\xa5\xb7\xc3\xc4\x5c\x13\xf7\x55\x68\x4a\x7d\xa5\xbe\xd0\x5d\xe1\x53\xdd\x0f\x04\xfc\x4a\xe5\x98\x3a\xe2\x03\x53\x3c\x5c\x8d\xf0\xa2\xba\x6e\x53\x43\x84\x22\xf1\xd3\x56\x1c\xf1\x5d\x01\x65\xb8\x97\x89\x01"
        }
    ]

testDerivation :: Derivation -> TestTree
testDerivation Derivation{..} = testCase (kemName derivKem) $ do
    let (sk, pk) = deriveKeyPair derivKem derivIkm
        skRm     = serializePrivate derivKem sk
        pkRm     = serialize derivKem pk
    assertEqual "private key mismatch" derivSkRm skRm
    assertEqual "public key mismatch" derivPkRm pkRm


{- Properties -}

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vectorOf i arbitraryBoundedRandom

instance Arbitrary Cipher where
    arbitrary =
        let kdf  = elements [ hkdf_sha256, hkdf_sha384, hkdf_sha512 ]
            aead = elements [ aead_aes128gcm, aead_aes256gcm
                            , aead_chacha20poly1305 ]
         in Cipher <$> kdf <*> aead

newtype Info = Info B.ByteString deriving Show

instance Arbitrary Info where
    arbitrary = Info <$> (choose(0, 80) >>= genByteString)

newtype Aad = Aad B.ByteString deriving Show

instance Arbitrary Aad where
    arbitrary = Aad <$> (choose(0, 120) >>= genByteString)

newtype Pt = Pt B.ByteString deriving Show

instance Arbitrary Pt where
    arbitrary = Pt <$> (choose(0, 512) >>= genByteString)

data PskInfo = PskInfo { psk :: B.ByteString, pskId :: B.ByteString }
    deriving Show

instance Arbitrary PskInfo where
    arbitrary = PskInfo <$> (choose(1, 50) >>= genByteString)
                        <*> (choose(1, 50) >>= genByteString)

prop_base :: SomeKEM -> Cipher -> Info -> Aad -> Pt -> Property
prop_base (SomeKEM kem) cipher (Info info) (Aad aad) (Pt pt) =
    forAll (arbitraryKeyPair kem) $ \pairR@(_, pkR) ->
        forAll (runDRG $ setupBaseS kem cipher pkR info) $ \r ->
            let (enc, ctxS) = throwCryptoError r
                ctxR = throwCryptoError $ setupBaseR kem cipher enc pairR info
                (ct, _)  = seal ctxS aad pt
                (pt', _) = open ctxR aad ct
             in (pt' == Just pt)

prop_psk :: SomeKEM -> Cipher -> Info -> Aad -> Pt -> PskInfo -> Property
prop_psk (SomeKEM kem) cipher (Info info) (Aad aad) (Pt pt) PskInfo{..} =
    forAll (arbitraryKeyPair kem) $ \pairR@(_, pkR) ->
        forAll (runDRG $ setupPSKS kem cipher pkR info psk pskId) $ \r ->
            let (enc, ctxS) = throwCryptoError r
                ctxR = throwCryptoError $ setupPSKR kem cipher enc pairR info psk pskId
                (ct, _)  = seal ctxS aad pt
                (pt', _) = open ctxR aad ct
             in (pt' == Just pt)

prop_auth :: SomeKEM -> Cipher -> Info -> Aad -> Pt -> Property
prop_auth (SomeKEM kem) cipher (Info info) (Aad aad) (Pt pt) =
    forAll (arbitraryKeyPair kem) $ \pairR@(_, pkR) ->
        forAll (arbitraryKeyPair kem) $ \pairS@(_, pkS) ->
            forAll (runDRG $ setupAuthS kem cipher pkR info pairS) $ \r ->
                let (enc, ctxS) = throwCryptoError r
                    ctxR = throwCryptoError $ setupAuthR kem cipher enc pairR info pkS
                    (ct, _)  = seal ctxS aad pt
                    (pt', _) = open ctxR aad ct
                 in (pt' == Just pt)

prop_auth_psk :: SomeKEM -> Cipher -> Info -> Aad -> Pt -> PskInfo -> Property
prop_auth_psk (SomeKEM kem) cipher (Info info) (Aad aad) (Pt pt) PskInfo{..} =
    forAll (arbitraryKeyPair kem) $ \pairR@(_, pkR) ->
        forAll (arbitraryKeyPair kem) $ \pairS@(_, pkS) ->
            forAll (runDRG $ setupAuthPSKS kem cipher pkR info psk pskId pairS) $ \r ->
                let (enc, ctxS) = throwCryptoError r
                    ctxR = throwCryptoError $ setupAuthPSKR kem cipher enc pairR info psk pskId pkS
                    (ct, _)  = seal ctxS aad pt
                    (pt', _) = open ctxR aad ct
                 in (pt' == Just pt)

{- Reference data -}

allKems :: [SomeKEM]
allKems =
    [ SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P256R1)))
    , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P384R1)))
    , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P521R1)))
    , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X25519)))
    , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X448)))
    ]

allStaticKems :: [SomeStaticKEM]
allStaticKems =
    [ SomeStaticKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P256R1)))
    , SomeStaticKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X25519)))
    , SomeStaticKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X448)))
    ]

allKdfs :: [KDF]
allKdfs = [ hkdf_sha256, hkdf_sha384, hkdf_sha512 ]

allAeads :: [AEAD]
allAeads = [ aead_aes128gcm, aead_aes256gcm, aead_chacha20poly1305 ]

findKEM :: KemID -> Maybe SomeStaticKEM
findKEM kemId = find (\(SomeStaticKEM e) -> kemID e == kemId) allStaticKems

findKDF :: KdfID -> Maybe KDF
findKDF kdfId = find (\e -> kdfID e == kdfId) allKdfs

findAEAD :: KdfID -> Maybe AEAD
findAEAD aeadId = find (\e -> aeadID e == aeadId) allAeads
