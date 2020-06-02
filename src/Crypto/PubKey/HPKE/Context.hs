-- |
-- Module      : Crypto.PubKey.HPKE.Context
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE RankNTypes #-}
module Crypto.PubKey.HPKE.Context
    ( Context(..)
    , nextNonce
    ) where

import qualified Data.ByteArray as B

import Crypto.PubKey.HPKE.AEAD
import Crypto.PubKey.HPKE.Imports


-- | HPKE context
data Context = Context
    { ctxEncrypt  :: forall aad ba a . (ByteArrayAccess aad, ByteArray ba) => (RunAEAD aad ba -> a) -> a
    , ctxDecrypt  :: forall aad ba a . (ByteArrayAccess aad, ByteArray ba) => (RunAEAD aad ba -> a) -> a
    , ctxTagLen   :: Int
    , ctxNonce    :: NonceAEAD
    , ctxExport   :: forall out . ByteArray out => ByteString -> Int -> out
    , ctxSeq      :: NonceAEAD
    }

nextNonce :: Context -> (NonceAEAD, Context)
nextNonce ctx =
    let nextSeq = fromJust "HPKE nonce overflow" $ incbe (ctxSeq ctx)
     in (ctxSeq ctx `B.xor` ctxNonce ctx, ctx { ctxSeq = nextSeq })

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
