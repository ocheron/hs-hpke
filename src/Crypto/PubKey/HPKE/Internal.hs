-- |
-- Module      : Crypto.PubKey.HPKE.Internal
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Internal HPKE classes, types and functions.
--
module Crypto.PubKey.HPKE.Internal
    ( GroupKEM(..)
    , GroupStaticKEM(..)
    , EllipticCurveGroup(..)
    , EllipticCurveStaticGroup(..)
    , changeRole
    ) where

import Crypto.PubKey.HPKE.Context
import Crypto.PubKey.HPKE.DHKEM
import Crypto.PubKey.HPKE.EC
