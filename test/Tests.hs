{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main (main) where

import qualified Data.ByteString as B
import Data.Proxy

import Crypto.ECC
import Crypto.Error

import Crypto.PubKey.HPKE as HPKE

import Test.Tasty
import Test.Tasty.QuickCheck

import Utils

instance Show HPKE.Context where
    show _ = "hpke-context"

data SomeKEM = forall kem . (AuthKEM kem, Show (KEMPrivate kem), Show (KEMPublic kem)) => SomeKEM (Proxy kem)

instance Arbitrary SomeKEM where
    arbitrary = elements
        [ SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_P256R1)))
        , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X25519)))
        , SomeKEM (Proxy :: Proxy (DHKEM (ECGroup Curve_X448)))
        ]

instance Show SomeKEM where
    show (SomeKEM kem) = kemName kem

main :: IO ()
main = defaultMain $ testGroup "hpke"
    [ testGroup "properties"
        [ testProperty "Base" prop_base
        , testProperty "PSK" prop_psk
        , testProperty "Auth" prop_auth
        , testProperty "AuthPSK" prop_auth_psk
        ]
    ]


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
