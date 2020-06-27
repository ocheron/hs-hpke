-- |
-- Module      : Crypto.PubKey.HPKE.Label
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.HPKE.Label
    ( labeledExtract
    , labeledExtractSalt
    , labeledExpand
    ) where

import qualified Data.ByteArray as B

import Crypto.Hash hiding (Context)
import Crypto.KDF.HKDF

import Crypto.PubKey.HPKE.Imports

labeledExtract :: (HashAlgorithm a, ByteArrayAccess ikm)
               => ([ByteString] -> [ByteString]) -> ikm -> PRK a
labeledExtract = labeledExtractSalt (B.empty :: Bytes)

labeledExtractSalt
    :: (HashAlgorithm a, ByteArrayAccess salt, ByteArrayAccess ikm)
    => salt -> ([ByteString] -> [ByteString]) -> ikm -> PRK a
labeledExtractSalt salt prependLabel ikm =
    let labeledIkm = B.concat $ "RFCXXXX " : prependLabel [ B.convert ikm ]
     in extract salt (labeledIkm :: Bytes)

labeledExpand :: (HashAlgorithm a, ByteArray ba)
              => PRK a -> ByteString -> [ByteString] -> Int -> ba
labeledExpand prk label infos len =
    let labeledInfo = B.concat $ be16 len ("RFCXXXX " : label : infos)
     in expand prk (labeledInfo :: Bytes) len
