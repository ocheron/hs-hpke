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

data SomeCompleteKEM = forall kem . (AuthKEM kem, StaticKEM kem, DeriveKEM kem, Show (KEMPrivate kem), Show (KEMPublic kem)) => SomeCompleteKEM (Proxy kem)

main :: IO ()
main = defaultMain $ testGroup "hpke"
    [ testCaseSteps "vectors" test_vectors
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
        (Just (SomeCompleteKEM kem), Just kdf, Just aead) -> do
            let cipher = Cipher kdf aead
                name   = kemName kem ++ ", " ++ kdfName kdf
                                     ++ ", " ++ aeadName aead
            case (vecPkSm, vecPsk, vecPskID) of
                (Just pkSm, Just psk, Just pskID) -> testAuthPSK name kem cipher psk pskID pkSm
                (Just pkSm, Nothing, Nothing)     -> testAuth name kem cipher pkSm
                (Nothing, Just psk, Just pskID)   -> testPSK name kem cipher psk pskID
                (Nothing, Nothing, Nothing)       -> testBase name kem cipher
                _                                 -> fail "invalid vector"
            testDeriveKey kem "recipient" vecIkmR vecSkRm vecPkRm
            case (vecIkmS, vecSkSm, vecPkSm) of
                (Just ikmS, Just skSm, Just pkSm)  -> testDeriveKey kem "sender" ikmS skSm pkSm
                (Nothing, Nothing, Nothing)        -> return ()
                _                                  -> fail "invalid sender ikm"
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
    testAuth name kem cipher pkSm = do
        step ("Auth: " ++ name)
        pkS <- fromCryptoPassed $ deserializePublic kem pkSm
        pairR <- fromCryptoPassed $ deserializePrivate kem vecSkRm
        ctx <- fromCryptoPassed $ setupAuthR kem cipher vecEnc pairR vecInfo pkS
        testBoth ctx vecExports vecEncryptions
    testAuthPSK name kem cipher psk pskID pkSm = do
        step ("AuthPSK: " ++ name)
        pkS <- fromCryptoPassed $ deserializePublic kem pkSm
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

    testDeriveKey kem name ikm skm pkm = do
        let (sk, pk) = deriveKeyPair kem ikm
            derivedSkm = serializePrivate kem sk
            derivedPkm = serializePublic kem pk
        assertEqual (name ++ " private key mismatch") skm derivedSkm
        assertEqual (name ++ " public key mismatch") pkm derivedPkm


{- Properties -}

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vectorOf i arbitraryBoundedRandom

genByteStringRange :: Int -> Int -> Gen B.ByteString
genByteStringRange low high = choose (low, high) >>= genByteString

instance Arbitrary Cipher where
    arbitrary =
        let kdf  = elements [ hkdf_sha256, hkdf_sha384, hkdf_sha512 ]
            aead = elements [ aead_aes128gcm, aead_aes256gcm
                            , aead_chacha20poly1305 ]
         in Cipher <$> kdf <*> aead

newtype Info = Info B.ByteString deriving Show

instance Arbitrary Info where
    arbitrary = Info <$> genByteStringRange 0 80

newtype Aad = Aad B.ByteString deriving Show

instance Arbitrary Aad where
    arbitrary = Aad <$> genByteStringRange 0 120

newtype Pt = Pt B.ByteString deriving Show

instance Arbitrary Pt where
    arbitrary = Pt <$> genByteStringRange 0 512

data PskInfo = PskInfo { psk :: B.ByteString, pskId :: B.ByteString }
    deriving Show

instance Arbitrary PskInfo where
    arbitrary = PskInfo <$> genByteStringRange 1 50
                        <*> genByteStringRange 1 50

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

allCompleteKems :: [SomeCompleteKEM]
allCompleteKems =
    [ SomeCompleteKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P256R1)))
    , SomeCompleteKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X25519)))
    , SomeCompleteKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X448)))
    ]

allKdfs :: [KDF]
allKdfs = [ hkdf_sha256, hkdf_sha384, hkdf_sha512 ]

allAeads :: [AEAD]
allAeads = [ aead_aes128gcm, aead_aes256gcm, aead_chacha20poly1305 ]

findKEM :: KemID -> Maybe SomeCompleteKEM
findKEM kemId = find (\(SomeCompleteKEM e) -> kemID e == kemId) allCompleteKems

findKDF :: KdfID -> Maybe KDF
findKDF kdfId = find (\e -> kdfID e == kdfId) allKdfs

findAEAD :: KdfID -> Maybe AEAD
findAEAD aeadId = find (\e -> aeadID e == aeadId) allAeads
