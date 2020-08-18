{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeSynonymInstances #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main (main) where

import Snmp

import Data.Bytes (Bytes)
import Data.Word (Word8,Word32)
import Net.IPv4 (IPv4,ipv4)
import Test.Tasty (defaultMain,TestTree,testGroup)
import Test.Tasty.QuickCheck (Arbitrary(..),testProperty,(===))

import qualified Data.Bytes as Bytes
import qualified Data.Primitive as Prim
import qualified Test.Tasty.QuickCheck as TQC

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests"
  [ testProperty "codec round-trip" $ \val ->
    let bs = encode val
        val' = decode bs
     in val' === Right val
  ]

instance Arbitrary Message where
  arbitrary = do
    let version = 2
    community <- arbitrary
    pdu <- arbitrary
    pure Message{version,community,pdu}

instance Arbitrary SomePdu where
  arbitrary = TQC.oneof
    [ GetRequest <$> arbitrary
    , GetNextRequest <$> arbitrary
    , GetBulkRequest <$> arbitrary
    , SetRequest <$> arbitrary
    , Response <$> arbitrary
    , InformRequest <$> arbitrary
    , Trap <$> arbitrary
    ]

instance Arbitrary Pdu where
  arbitrary = do
    requestId <- arbitrary
    errorStatus <- arbitrary
    errorIndex <- arbitrary
    varBinds <- Prim.smallArrayFromList <$> arbitrary
    pure Pdu{requestId,errorStatus,errorIndex,varBinds}

instance Arbitrary BulkPdu where
  arbitrary = do
    requestId <- arbitrary
    nonRepeaters <- arbitrary
    maxRepetitions <- arbitrary
    varBinds <- Prim.smallArrayFromList <$> arbitrary
    pure BulkPdu{requestId,nonRepeaters,maxRepetitions,varBinds}

instance Arbitrary VarBind where
  arbitrary = do
    name <- arbitrary
    result <- arbitrary
    pure VarBind{name,result}

instance Arbitrary VarBindResult where
  arbitrary = TQC.oneof
    [ IntVal <$> arbitrary
    , StrVal <$> arbitrary
    , OidVal <$> arbitrary -- ObjectId
    , IpVal <$> arbitrary -- IPv4
    , CounterVal <$> arbitrary
    , UIntVal <$> arbitrary
    , TimeTicksVal <$> arbitrary
    , ArbitraryVal <$> arbitrary
    , BigCounterVal <$> arbitrary
    , pure Unspecified
    , pure NoSuchObject
    , pure NoSuchInstance
    , pure EndOfMibView
    ]

instance Arbitrary ErrorStatus where
  arbitrary = TQC.elements
    [ NoError
    , TooBig
    , NoSuchName
    , BadValue
    , ReadOnly
    , GenErr
    , NoAccess
    , WrongType
    , WrongLength
    , WrongEncoding
    , WrongValue
    , NoCreation
    , InconsistentValue
    , ResourceUnavailable
    , CommitFailed
    , UndoFailed
    , AuthorizationError
    , NotWritable
    , InconsistentName
    ]

instance Arbitrary Bytes where
  arbitrary = do
    bs :: [Word8] <-  TQC.arbitrary
    pure $ Bytes.fromByteArray $ Prim.byteArrayFromList bs

instance Arbitrary IPv4 where
  arbitrary = ipv4 <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ObjectId where
  arbitrary = do
    b1 <- TQC.elements [0..2]
    b2 <- TQC.elements [0..39]
    bs :: [Word32] <-  arbitrary
    pure $ Prim.primArrayFromList (b1:b2:bs)
