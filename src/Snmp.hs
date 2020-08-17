{-# language ApplicativeDo #-}
{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language NamedFieldPuns #-}
{-# language TypeApplications #-}

module Snmp
  ( Message(..)
  , SomePdu(..)
  , Pdu(..)
  , BulkPdu(..)
  , VarBind(..)
  , VarBindResult(..)
  , ErrorStatus(..)
  , encode
  , decode
  ) where

import Asn.Ber (Value(..),Contents(..),Class(..))
import Asn.Resolve.Category ((>->))
import Control.Monad ((<=<))
import Data.Bifunctor (first)
import Data.Bytes (Bytes)
import Data.Int (Int32,Int64)
import Data.Primitive (PrimArray,SmallArray,smallArrayFromListN)
import Data.Word (Word32,Word64)
import Net.IPv4 (IPv4, ipv4)

import qualified Asn.Ber as Asn
import qualified Asn.Ber.Encode as Asn
import qualified Asn.Resolve.Category as Asn
import qualified Data.Bytes as Bytes
import qualified Data.Primitive as Prim
import qualified Net.IPv4 as IPv4


type ObjectId = PrimArray Word32 -- FIXME there really should be an ObjectId type in Asn module

data Message = Message
  { version :: Int
  , community :: Bytes
  , pdu :: SomePdu
  }
  deriving(Show)

------ PDUs ------

data SomePdu
  = GetRequest Pdu
  | GetNextRequest Pdu
  | GetBulkRequest BulkPdu
  | SetRequest Pdu
  | Response Pdu
  | InformRequest Pdu
  | Trap Pdu
  deriving(Show)

data Pdu = Pdu
  { requestId :: Int32
  , errorStatus :: ErrorStatus
  , errorIndex :: Int
  , varBinds :: SmallArray VarBind
  }
  deriving(Show)

data BulkPdu = BulkPdu
  { requestId :: Int32
  , nonRepeaters :: Word32
  , maxRepetitions :: Word32
  , varBinds :: SmallArray VarBind
  }
  deriving(Show)

------ Variable Bindings ------

data VarBind = VarBind
  { name :: ObjectId
  , result :: VarBindResult
  }
  deriving(Show)

data VarBindResult
  = IntVal Int32
  | StrVal Bytes
  | OidVal ObjectId
  | IpVal IPv4
  | CounterVal Word32
  | UIntVal Word32
  | TimeTicksVal Word32
  | ArbitraryVal Bytes
  | BigCounterVal Word64 -- TODO can I merge CounterVal into this one?
  | Unspecified
  | NoSuchObject
  | NoSuchInstance
  | EndOfMibView
  deriving(Show)

data ErrorStatus
  = NoError
  | TooBig
  | NoSuchName
  | BadValue
  | ReadOnly
  | GenErr
  | NoAccess
  | WrongType
  | WrongLength
  | WrongEncoding
  | WrongValue
  | NoCreation
  | InconsistentValue
  | ResourceUnavailable
  | CommitFailed
  | UndoFailed
  | AuthorizationError
  | NotWritable
  | InconsistentName
  deriving(Show,Eq)

------ ASN.1 Codec ------

decode :: Bytes -> Either String Message
decode = first show . resolveMessage <=< Asn.decode

resolveMessage :: Value -> Either Asn.Path Message
resolveMessage = Asn.run resoveMessage

resoveMessage :: Asn.Parser Value Message
resoveMessage = Asn.sequence >-> do
  version <- fromIntegral @Int64 @Int <$> (Asn.index 0 >-> Asn.integer)
  community <- Asn.index 1 >-> Asn.octetString
  pdu <- Asn.index 2 >-> resolveSomePdu
  pure Message{version,community,pdu}
  where
  resolveSomePdu = Asn.chooseTag
    [ (ContextSpecific, 0, GetRequest <$> pdu)
    , (ContextSpecific, 1, GetNextRequest <$> pdu)
    , (ContextSpecific, 2, GetBulkRequest <$> bulkPdu)
    , (ContextSpecific, 3, Response <$> pdu)
    , (ContextSpecific, 4, SetRequest <$> pdu)
    , (ContextSpecific, 5, InformRequest <$> pdu)
    , (ContextSpecific, 6, Trap <$> pdu)
    ]
  pdu :: Asn.Parser Value Pdu
  pdu = Asn.sequence >-> do
    requestId <- fromIntegral @Int64 @Int32 <$> Asn.index 0 >-> Asn.integer
    errorStatus <- Asn.index 1 >-> Asn.integer >-> Asn.arr parseErrorStatus
    errorIndex <- fromIntegral @Int64 @Int <$> (Asn.index 2 >-> Asn.integer)
    varBinds <- Asn.index 3 >-> Asn.sequenceOf (Asn.sequence >-> varBind)
    pure Pdu{requestId,errorStatus,errorIndex,varBinds}
  bulkPdu :: Asn.Parser Value BulkPdu
  bulkPdu = Asn.sequence >-> do
    requestId <- fromIntegral @Int64 @Int32 <$> Asn.index 0 >-> Asn.integer
    nonRepeaters <- fromIntegral @Int64 @Word32 <$> Asn.index 1 >-> Asn.integer
    maxRepetitions <- fromIntegral @Int64 @Word32 <$> Asn.index 2 >-> Asn.integer
    varBinds <- Asn.index 3 >-> Asn.sequenceOf (Asn.sequence >-> varBind)
    pure BulkPdu{requestId,nonRepeaters,maxRepetitions,varBinds}
  varBind :: Asn.Parser (SmallArray Value) VarBind
  varBind = do
      name <- Asn.index 0 >-> Asn.oid
      result <- Asn.index 1 >-> varBindResult
      pure VarBind{name,result}
  varBindResult :: Asn.Parser Value VarBindResult
  varBindResult = Asn.chooseTag
    [ (Universal, 2, (IntVal . fromIntegral @Int64 @Int32) <$> Asn.integer)
    , (Universal, 4, StrVal <$> Asn.octetString)
    , (Universal, 6, OidVal <$> Asn.oid)
    , (Application, 0, (IpVal . ipFromBytes) <$> Asn.octetString)
    , (Application, 1, (CounterVal . fromIntegral @Int64 @Word32) <$> Asn.integer)
    , (Application, 2, (UIntVal . fromIntegral @Int64 @Word32) <$> Asn.integer)
    , (Application, 3, (TimeTicksVal . fromIntegral @Int64 @Word32) <$> Asn.integer)
    , (Application, 4, ArbitraryVal <$> Asn.octetString)
    , (Application, 6, (BigCounterVal . fromIntegral @Int64 @Word64) <$> Asn.integer)
    , (Universal, 5, Unspecified <$ Asn.null)
    , (ContextSpecific, 0, NoSuchObject <$ Asn.null)
    , (ContextSpecific, 1, NoSuchInstance <$ Asn.null)
    , (ContextSpecific, 2, EndOfMibView <$ Asn.null)
    ]
  ipFromBytes :: Bytes -> IPv4
  ipFromBytes bs = 
    let a = Bytes.unsafeIndex bs 0
        b = Bytes.unsafeIndex bs 1
        c = Bytes.unsafeIndex bs 2
        d = Bytes.unsafeIndex bs 3
     in ipv4 a b c d

encode :: Message -> Bytes
encode = Asn.encode . msgValue
  where
  msgValue Message{version,community,pdu} =
    Value Universal 16 $ Constructed $ smallArrayFromListN 3
      [ Value Universal 2 $ Integer $ fromIntegral @Int @Int64 version
      , Value Universal 4 $ OctetString community
      , somePduValue pdu
      ]
  somePduValue (GetRequest pdu) = Value ContextSpecific 0 $ pduValue pdu
  somePduValue (GetNextRequest pdu) = Value ContextSpecific 1 $ pduValue pdu
  somePduValue (GetBulkRequest BulkPdu{requestId,nonRepeaters,maxRepetitions,varBinds}) =
    Value ContextSpecific 5 $
      Constructed $ smallArrayFromListN 4
        [ Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 requestId
        , Value Universal 2 $ Integer $ fromIntegral @Word32 @Int64 nonRepeaters
        , Value Universal 2 $ Integer $ fromIntegral @Word32 @Int64 maxRepetitions
        , Value Universal 16 $ Constructed $ Prim.mapSmallArray' varBindValue varBinds
        ]
  somePduValue (SetRequest pdu) = Value ContextSpecific 3 $ pduValue pdu
  somePduValue (Response pdu) = Value ContextSpecific 2 $ pduValue pdu
  somePduValue (InformRequest pdu) = Value ContextSpecific 6 $ pduValue pdu
  somePduValue (Trap pdu) = Value ContextSpecific 7 $ pduValue pdu
  pduValue Pdu{requestId, errorStatus, errorIndex, varBinds} =
    Constructed $ smallArrayFromListN 4
      [ Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 requestId
      , Value Universal 2 $ Integer $ serializeErrorStatus errorStatus
      , Value Universal 2 $ Integer $ fromIntegral @Int @Int64 errorIndex
      , Value Universal 16 $ Constructed $ Prim.mapSmallArray' varBindValue varBinds
      ]
  varBindValue VarBind{name,result}=
    Value Universal 16 $ Constructed $ smallArrayFromListN 2
      [ Value Universal 6 $ ObjectIdentifier name
      , resultValue result
      ]
  resultValue (IntVal i) = Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 i
  resultValue (StrVal bs) = Value Universal 4 $ OctetString bs
  resultValue (OidVal oid) = Value Universal 6 $ ObjectIdentifier oid
  resultValue (IpVal ip) = Value Application 0 $ OctetString (ipToBytes ip)
  resultValue (CounterVal i) = Value Application 1 $ Integer $ fromIntegral @Word32 @Int64 i
  resultValue (UIntVal i) = Value Application 2 $ Integer $ fromIntegral @Word32 @Int64 i
  resultValue (TimeTicksVal i) = Value Application 3 $ Integer $ fromIntegral @Word32 @Int64 i
  resultValue (ArbitraryVal bs) = Value Application 4 $ OctetString bs
  resultValue (BigCounterVal i) = Value Application 6 $ Integer $ fromIntegral @Word64 @Int64 i
  resultValue Unspecified = Value Universal 5 Null
  resultValue NoSuchObject = Value ContextSpecific 0 Null
  resultValue NoSuchInstance = Value ContextSpecific 1 Null
  resultValue EndOfMibView = Value ContextSpecific 2 Null
  ipToBytes ip = let (a, b, c, d) = IPv4.toOctets ip
    in Bytes.fromByteArray $ Prim.byteArrayFromListN 4 [a, b, c, d]

parseErrorStatus :: Int64 -> Maybe ErrorStatus
parseErrorStatus = \case
  0 -> Just NoError
  1 -> Just TooBig
  2 -> Just NoSuchName
  3 -> Just BadValue
  4 -> Just ReadOnly
  5 -> Just GenErr
  6 -> Just NoAccess
  7 -> Just WrongType
  8 -> Just WrongLength
  9 -> Just WrongEncoding
  10 -> Just WrongValue
  11 -> Just NoCreation
  12 -> Just InconsistentValue
  13 -> Just ResourceUnavailable
  14 -> Just CommitFailed
  15 -> Just UndoFailed
  16 -> Just AuthorizationError
  17 -> Just NotWritable
  18 -> Just InconsistentName
  _ -> Nothing
serializeErrorStatus :: ErrorStatus -> Int64
serializeErrorStatus = \case
  NoError -> 0
  TooBig -> 1
  NoSuchName -> 2
  BadValue -> 3
  ReadOnly -> 4
  GenErr -> 5
  NoAccess -> 6
  WrongType -> 7
  WrongLength -> 8
  WrongEncoding -> 9
  WrongValue -> 10
  NoCreation -> 11
  InconsistentValue -> 12
  ResourceUnavailable -> 13
  CommitFailed -> 14
  UndoFailed -> 15
  AuthorizationError -> 16
  NotWritable -> 17
  InconsistentName -> 18

------ JSON Codec ------
