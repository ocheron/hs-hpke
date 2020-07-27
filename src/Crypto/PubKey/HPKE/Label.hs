-- |
-- Module      : Crypto.PubKey.HPKE.Label
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.HPKE.Label
    ( SuiteId
    , labeledExtract
    , labeledExtractSalt
    , labeledExpand
    ) where

import qualified Data.ByteArray as B

import Crypto.Hash hiding (Context)
import Crypto.KDF.HKDF

import Crypto.PubKey.HPKE.Imports

type SuiteId = [ByteString] -> [ByteString]

labeledExtract :: (HashAlgorithm a, ByteArrayAccess ikm)
               => SuiteId -> ByteString -> ikm -> PRK a
labeledExtract = labeledExtractSalt (B.empty :: Bytes)

labeledExtractSalt
    :: (HashAlgorithm a, ByteArrayAccess salt, ByteArrayAccess ikm)
    => salt -> SuiteId -> ByteString -> ikm -> PRK a
labeledExtractSalt salt sid label ikm =
    let labeledIkm = B.concat $ "HPKE-05 " : sid [ label, B.convert ikm ]
     in extract salt (labeledIkm :: Bytes)

labeledExpand :: (HashAlgorithm a, ByteArray ba)
              => PRK a -> SuiteId -> ByteString -> [ByteString] -> Int -> ba
labeledExpand prk sid label infos len =
    let labeledInfo = B.concat $ be16 len ("HPKE-05 " : sid (label : infos))
     in expand prk (labeledInfo :: Bytes) len
