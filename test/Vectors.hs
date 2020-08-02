{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Vectors
    ( Vector(..)
    , Encryption(..)
    , Export(..)
    , readVectors
    ) where

import Data.Aeson
import Data.Aeson.Types
import Data.Char
import Data.ByteString (ByteString, cons, empty)
import qualified Data.ByteString.Lazy as L
import Data.List (sortBy)
import Data.Text (Text, uncons)

import qualified Codec.Compression.GZip as GZip

data Encryption = Encryption
    { ePlaintext  :: ByteString
    , eAAD        :: ByteString
    , eCiphertext :: ByteString
    } deriving Show

instance FromJSON Encryption where
    parseJSON = withObject "Encryption" $ \o -> Encryption
        <$> o .:: "plaintext"
        <*> o .:: "aad"
        <*> o .:: "ciphertext"

data Export = Export
    { eContext  :: ByteString
    , eLength   :: Int
    , eValue    :: ByteString
    } deriving Show

instance FromJSON Export where
    parseJSON = withObject "Export" $ \o -> Export
        <$> o .:: "exportContext"
        <*> o .:  "exportLength"
        <*> o .:: "exportValue"

data Vector = Vector
    { vecMode        :: Int
    , vecKemID       :: Int
    , vecKdfID       :: Int
    , vecAeadID      :: Int
    , vecInfo        :: ByteString
    , vecSeedS       :: Maybe ByteString
    , vecSkSm        :: Maybe ByteString
    , vecPkSm        :: Maybe ByteString
    , vecSeedR       :: ByteString
    , vecSkRm        :: ByteString
    , vecPkRm        :: ByteString
    , vecPsk         :: Maybe ByteString
    , vecPskID       :: Maybe ByteString
    , vecEnc         :: ByteString
    , vecEncryptions :: [Encryption]
    , vecExports     :: [Export]
    } deriving Show

instance FromJSON Vector where
    parseJSON = withObject "Vector" $ \v -> Vector
        <$>  v .:   "mode"
        <*>  v .:   "kem_id"
        <*>  v .:   "kdf_id"
        <*>  v .:   "aead_id"
        <*>  v .::  "info"
        <*>  v .::? "seedS"
        <*>  v .::? "skSm"
        <*>  v .::? "pkSm"
        <*>  v .::  "seedR"
        <*>  v .::  "skRm"
        <*>  v .::  "pkRm"
        <*>  v .::? "psk"
        <*>  v .::? "psk_id"
        <*>  v .::  "enc"
        <*>  v .:   "encryptions"
        <*>  v .:   "exports"

readVectors :: FilePath -> IO [Vector]
readVectors path = do
    bs <- L.readFile path
    case decode (GZip.decompress bs) of
        Just vecs -> return $ sortVectors vecs
        _         -> fail "could not parse"

sortVectors :: [Vector] -> [Vector]
sortVectors = sortBy comp
  where
    -- we want X25519 and X448 to come first, then the other KEMs
    key Vector{..} = (vecKemID < 0x0020, vecKemID, vecKdfID, vecAeadID, vecMode)
    comp a b = key a `compare` key b

(.::) :: Object -> Text -> Parser ByteString
o .:: name = (o .: name) >>= fromBase16

(.::?) :: Object -> Text -> Parser (Maybe ByteString)
o .::? name = (o .:? name) >>= opt fromBase16

opt :: Monad m => (a -> m b) -> Maybe a -> m (Maybe b)
opt f = maybe (return Nothing) (fmap Just . f)

fromBase16 :: Text -> Parser ByteString
fromBase16 t = case uncons t of
    Nothing      -> return empty
    Just (a, as) ->
        case uncons as of
            Nothing      -> fail "incomplete Base16"
            Just (b, bs) -> do
                ia <- fromHexDigit a
                ib <- fromHexDigit b
                let w  = fromIntegral (ia * 16 + ib)
                cons w <$> fromBase16 bs

fromHexDigit :: Char -> Parser Int
fromHexDigit c
    | isHexDigit c = return (digitToInt c)
    | otherwise    = fail "invalid hex digit"
