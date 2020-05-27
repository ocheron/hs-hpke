{-# LANGUAGE NoImplicitPrelude #-}
-- |
-- Module      : Crypto.PubKey.HPKE.Imports
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
module Crypto.PubKey.HPKE.Imports
    (
    -- generic exports
      ByteString
    , Bytes
    , ScrubbedBytes
    , ByteArray
    , ByteArrayAccess
    , module Control.Applicative
    , module Control.Monad
    , module Data.Bits
    , module Data.List
    , module Data.Maybe
    , module Data.Word
    -- project definition
    , be16
    , fromJust
    ) where

import Data.ByteArray
import Data.ByteString (ByteString)

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.List
import Data.Maybe hiding (fromJust)
import Data.Word

import qualified Prelude as P

be16 :: (P.Integral a, Bits a) => a -> [ByteString] -> [ByteString]
be16 val xs =
    let len_hi = singleton (P.fromIntegral (val `shiftR` 8))
        len_lo = singleton (P.fromIntegral  val)
     in len_hi : len_lo : xs

fromJust :: P.String -> Maybe a -> a
fromJust what Nothing  = P.error ("fromJust " ++ what ++ ": Nothing") -- yuck
fromJust _    (Just x) = x
