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
import Data.Memory.Endian

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.List
import Data.Maybe hiding (fromJust)
import Data.Word

import Foreign.Storable (pokeByteOff)

import qualified Prelude as P

be16 :: (ByteArray ba, P.Integral a) => a -> [ba] -> [ba]
be16 val xs =
    let w16 = P.fromIntegral val :: Word16
        len = w16 `P.seq` unsafeCreate 2 (\p -> pokeByteOff p 0 (toBE w16))
     in len : xs
{-# INLINABLE be16 #-}

fromJust :: P.String -> Maybe a -> a
fromJust what Nothing  = P.error ("fromJust " ++ what ++ ": Nothing") -- yuck
fromJust _    (Just x) = x
