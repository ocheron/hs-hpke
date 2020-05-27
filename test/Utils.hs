{-# LANGUAGE RankNTypes #-}
module Utils
    ( runDRG
    , arbitraryKeyPair
    ) where

import Test.Tasty.QuickCheck

import Data.Word

import Crypto.Random

import Crypto.PubKey.HPKE

-- Generate a random input to drgNewTest.  The default Arbitrary instance
-- would have a bias towards small Word64 values and high probabiliy to return
-- the same DRG twice.  Distribution of arbitraryBoundedRandom is uniform.
arbitraryTestDRG :: Gen (Word64, Word64, Word64, Word64, Word64)
arbitraryTestDRG = (,,,,) <$> arbitraryBoundedRandom
                          <*> arbitraryBoundedRandom
                          <*> arbitraryBoundedRandom
                          <*> arbitraryBoundedRandom
                          <*> arbitraryBoundedRandom

runDRG :: (forall m . MonadRandom m => m a) -> Gen a
runDRG r = (f . drgNewTest) `fmap` arbitraryTestDRG
  where f rng = fst $ withDRG rng r

arbitraryKeyPair :: KEM kem
                 => proxy kem
                 -> Gen (KEMPrivate kem, KEMPublic kem)
arbitraryKeyPair grp = runDRG (generateKeyPair grp)
