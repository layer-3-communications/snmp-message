{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeApplications #-}

module Snmp
  ( -- * V2
    Message(..)
  , Pdus(..)
  , Pdu(..)
  , BulkPdu(..)
  , VarBind(..)
  , VarBindResult(..)
  , ErrorStatus(..)
    -- * V3
  , MessageV3(..)
  , HeaderData(..)
  , AuthProtocol(..)
  , PrivProtocol(..)
  , SecurityParameters(..)
  , ScopedPdu(..)
  , ScopedPduData(..)
    -- * Auth Protocols
  , pattern NoAuthProtocol
  , pattern HmacMd5AuthProtocol
  , pattern HmacShaAuthProtocol
  , pattern HmacSha256AuthProtocol
  , pattern HmacSha512AuthProtocol
    -- * Priv Protocols
  , pattern NoPrivProtocol
  , pattern DesPrivProtocol
  , pattern AesPrivProtocol
  , pattern Aes256PrivProtocol
    -- * Codec
  , encodeMessage
  , encodeMessageV3
  , decodeMessage
  , decodeMessageV3
  , encodeScopedPdu
  , decodeScopedPdu
  , decodeSecurityParameters
  , encodeSecurityParameters
  ) where

import Prelude hiding (id)

import Asn.Ber (Value(..),Contents(..),Class(..))
import Asn.Oid (Oid(..))
import Asn.Resolve.Category ((>->))
import Data.Bytes (Bytes)
import Data.Int (Int32,Int64)
import Data.Primitive (SmallArray,smallArrayFromListN)
import Data.Word (Word8,Word32,Word64)
import Net.IPv4 (IPv4, ipv4)

import qualified Asn.Ber as Asn
import qualified Arithmetic.Nat as Nat
import qualified Asn.Resolve.Category as Asn
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Builder.Bounded as BBB
import qualified Data.Primitive as Prim
import qualified Data.Primitive.Contiguous as C
import qualified Net.IPv4 as IPv4


data Message = Message
  { version :: !Int32
    -- ^ Should be set to 2.
  , community :: {-# UNPACK #-} !Bytes
  , pdu :: Pdus
  }
  deriving stock (Show,Eq)

------ PDUs ------

data Pdus
  = GetRequest Pdu
  | GetNextRequest Pdu
  | GetBulkRequest BulkPdu
  | SetRequest Pdu
  | Response Pdu
  | InformRequest Pdu
  | Trap Pdu
  | Report Pdu
    -- ^ Reports used by SNMPv3.
  deriving stock (Show,Eq)

data Pdu = Pdu
  { requestId :: !Int32
  , errorStatus :: !ErrorStatus
  , errorIndex :: !Int
  , varBinds :: !(SmallArray VarBind)
  }
  deriving stock (Show,Eq)

data BulkPdu = BulkPdu
  { requestId :: !Int32
  , nonRepeaters :: !Word32
  , maxRepetitions :: !Word32
  , varBinds :: !(SmallArray VarBind)
  }
  deriving stock (Show,Eq)

------ Variable Bindings ------

data VarBind = VarBind
  { name :: !Oid
  , result :: !VarBindResult
  }
  deriving stock (Show,Eq)

data VarBindResult
  = IntVal !Int32
  | StrVal {-# UNPACK #-} !Bytes
  | OidVal !Oid
  | IpVal !IPv4
  | CounterVal !Word32
  | UIntVal !Word32
  | TimeTicksVal !Word32
  | ArbitraryVal {-# UNPACK #-} !Bytes
  | BigCounterVal !Word64
  | Unspecified
  | NoSuchObject
  | NoSuchInstance
  | EndOfMibView
  deriving stock (Show,Eq)

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
  deriving stock (Show,Eq)

------ ASN.1 Codec ------

decodeMessage :: Value -> Either Asn.Path Message
decodeMessage = Asn.run parserMessage

decodeMessageV3 :: Value -> Either Asn.Path MessageV3
decodeMessageV3 = Asn.run parserMessageV3

decodeSecurityParameters :: Value -> Either Asn.Path SecurityParameters
decodeSecurityParameters = Asn.run parserSecurityParameters

decodeScopedPdu :: Value -> Either Asn.Path ScopedPdu
decodeScopedPdu = Asn.run parserScopedPdu

parserMessageV3 :: Asn.Parser Value MessageV3
parserMessageV3 = Asn.sequence >-> do
  version <- fromIntegral @Int64 @Int32 <$> (Asn.index 0 >-> Asn.integer)
  globalData <- Asn.index 1 >-> parserHeaderData
  securityParameters <- Asn.index 2 >-> Asn.octetString
  data_ <- Asn.index 3 >-> parserScopedPduData
  pure MessageV3{version,globalData,securityParameters,data_}

parserSecurityParameters :: Asn.Parser Value SecurityParameters
parserSecurityParameters = Asn.sequence >-> do
  authoritativeEngineId <- Asn.index 0 >-> Asn.octetString
  authoritativeEngineBoots <- fromIntegral @Int64 @Int32 <$> (Asn.index 1 >-> Asn.integer)
  authoritativeEngineTime <- fromIntegral @Int64 @Int32 <$> (Asn.index 2 >-> Asn.integer)
  userName <- Asn.index 3 >-> Asn.octetString
  authenticationParameters <- Asn.index 4 >-> Asn.octetString
  privacyParameters <- Asn.index 5 >-> Asn.octetString
  pure SecurityParameters
    {authoritativeEngineId,authoritativeEngineBoots,authoritativeEngineTime
    ,userName,authenticationParameters,privacyParameters
    }

parserScopedPduData :: Asn.Parser Value ScopedPduData
parserScopedPduData = Asn.chooseTag
  [ (Universal, 4, ScopedPduDataEncrypted <$> Asn.octetString)
  , (Universal, 16, ScopedPduDataPlaintext <$> parserScopedPdu)
  ]

parserHeaderData :: Asn.Parser Value HeaderData
parserHeaderData = Asn.sequence >-> do
  id <- fromIntegral @Int64 @Int32 <$> (Asn.index 0 >-> Asn.integer)
  maxSize <- fromIntegral @Int64 @Int32 <$> (Asn.index 1 >-> Asn.integer)
  flags <- Asn.index 2 >-> Asn.octetStringSingleton
  securityModel <- fromIntegral @Int64 @Int32 <$> (Asn.index 3 >-> Asn.integer)
  pure HeaderData{id,maxSize,flags,securityModel}

parserScopedPdu :: Asn.Parser Value ScopedPdu
parserScopedPdu = Asn.sequence >-> do
  contextEngineId <- Asn.index 0 >-> Asn.octetString
  contextName <- Asn.index 1 >-> Asn.octetString
  data_ <- Asn.index 2 >-> parserPdus
  pure ScopedPdu{contextEngineId,contextName,data_}

parserMessage :: Asn.Parser Value Message
parserMessage = Asn.sequence >-> do
  version <- fromIntegral @Int64 @Int32 <$> (Asn.index 0 >-> Asn.integer)
  community <- Asn.index 1 >-> Asn.octetString
  pdu <- Asn.index 2 >-> parserPdus
  pure Message{version,community,pdu}

parserPdus :: Asn.Parser Value Pdus
parserPdus = Asn.chooseTag
  [ (ContextSpecific, 0, GetRequest <$> parserPdu)
  , (ContextSpecific, 1, GetNextRequest <$> parserPdu)
  , (ContextSpecific, 5, GetBulkRequest <$> parserBulkPdu)
  , (ContextSpecific, 2, Response <$> parserPdu)
  , (ContextSpecific, 3, SetRequest <$> parserPdu)
  , (ContextSpecific, 6, InformRequest <$> parserPdu)
  , (ContextSpecific, 7, Trap <$> parserPdu)
  , (ContextSpecific, 8, Report <$> parserPdu)
  ]

parserPdu :: Asn.Parser Value Pdu
parserPdu = Asn.sequence >-> do
  requestId <- fromIntegral @Int64 @Int32 <$> Asn.index 0 >-> Asn.integer
  errorStatus <- Asn.index 1 >-> Asn.integer >-> Asn.arr parseErrorStatus
  errorIndex <- fromIntegral @Int64 @Int <$> (Asn.index 2 >-> Asn.integer)
  varBinds <- Asn.index 3 >-> Asn.sequenceOf (Asn.sequence >-> parserVarBind)
  pure Pdu{requestId,errorStatus,errorIndex,varBinds}

parserBulkPdu :: Asn.Parser Value BulkPdu
parserBulkPdu = Asn.sequence >-> do
  requestId <- fromIntegral @Int64 @Int32 <$> Asn.index 0 >-> Asn.integer
  nonRepeaters <- fromIntegral @Int64 @Word32 <$> Asn.index 1 >-> Asn.integer
  maxRepetitions <- fromIntegral @Int64 @Word32 <$> Asn.index 2 >-> Asn.integer
  varBinds <- Asn.index 3 >-> Asn.sequenceOf (Asn.sequence >-> parserVarBind)
  pure BulkPdu{requestId,nonRepeaters,maxRepetitions,varBinds}

parserVarBind :: Asn.Parser (SmallArray Value) VarBind
parserVarBind = do
  name <- Asn.index 0 >-> Asn.oid
  result <- Asn.index 1 >-> parserVarBindResult
  pure VarBind{name,result}

parserVarBindResult :: Asn.Parser Value VarBindResult
parserVarBindResult = Asn.chooseTag
  [ (Universal, 2, (IntVal . fromIntegral @Int64 @Int32) <$> Asn.integer)
  , (Universal, 4, StrVal <$> Asn.octetString)
  , (Universal, 6, OidVal <$> Asn.oid)
  , (Application, 0, Asn.octetString >-> ipFromBytes)
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

ipFromBytes :: Asn.Parser Bytes VarBindResult
{-# inline ipFromBytes #-}
ipFromBytes = Asn.arr
  (\bs -> if Bytes.length bs == 4
    then
      let a = Bytes.unsafeIndex bs 0
          b = Bytes.unsafeIndex bs 1
          c = Bytes.unsafeIndex bs 2
          d = Bytes.unsafeIndex bs 3
       in Just (IpVal (ipv4 a b c d))
    else Nothing
  )

encodeMessage :: Message -> Asn.Value
encodeMessage Message{version,community,pdu} =
  Value Universal 16 $ Constructed $ C.tripleton
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 version)
    (Value Universal 4 $ OctetString community)
    (encodePdus pdu)

encodePdus :: Pdus -> Asn.Value
encodePdus (GetRequest pdu) = Value ContextSpecific 0 $ encodePdu pdu
encodePdus (GetNextRequest pdu) = Value ContextSpecific 1 $ encodePdu pdu
encodePdus (GetBulkRequest BulkPdu{requestId,nonRepeaters,maxRepetitions,varBinds}) =
  Value ContextSpecific 5 $
    Constructed $ C.quadrupleton
      (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 requestId)
      (Value Universal 2 $ Integer $ fromIntegral @Word32 @Int64 nonRepeaters)
      (Value Universal 2 $ Integer $ fromIntegral @Word32 @Int64 maxRepetitions)
      (Value Universal 16 $ Constructed $ Prim.mapSmallArray' encodeVarBind varBinds)
encodePdus (SetRequest pdu) = Value ContextSpecific 3 $ encodePdu pdu
encodePdus (Response pdu) = Value ContextSpecific 2 $ encodePdu pdu
encodePdus (InformRequest pdu) = Value ContextSpecific 6 $ encodePdu pdu
encodePdus (Trap pdu) = Value ContextSpecific 7 $ encodePdu pdu
encodePdus (Report pdu) = Value ContextSpecific 8 $ encodePdu pdu

encodePdu :: Pdu -> Asn.Contents
encodePdu Pdu{requestId, errorStatus, errorIndex, varBinds} =
  Constructed $ C.quadrupleton
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 requestId)
    (Value Universal 2 $ Integer $ serializeErrorStatus errorStatus)
    (Value Universal 2 $ Integer $ fromIntegral @Int @Int64 errorIndex)
    (Value Universal 16 $ Constructed $ Prim.mapSmallArray' encodeVarBind varBinds)

encodeVarBind :: VarBind -> Asn.Value
encodeVarBind VarBind{name,result}=
  Value Universal 16 $ Constructed $ C.doubleton
    (Value Universal 6 $ ObjectIdentifier name)
    (encodeVarBindResult result)

ipToBytes :: IPv4 -> Bytes
{-# inline ipToBytes #-}
ipToBytes ip = Bytes.fromByteArray (BBB.run Nat.constant (IPv4.boundedBuilderOctetsBE ip))

encodeVarBindResult :: VarBindResult -> Asn.Value
encodeVarBindResult (IntVal i) = Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 i
encodeVarBindResult (StrVal bs) = Value Universal 4 $ OctetString bs
encodeVarBindResult (OidVal oid) = Value Universal 6 $ ObjectIdentifier oid
encodeVarBindResult (IpVal ip) = Value Application 0 $ OctetString (ipToBytes ip)
encodeVarBindResult (CounterVal i) = Value Application 1 $ Integer $ fromIntegral @Word32 @Int64 i
encodeVarBindResult (UIntVal i) = Value Application 2 $ Integer $ fromIntegral @Word32 @Int64 i
encodeVarBindResult (TimeTicksVal i) = Value Application 3 $ Integer $ fromIntegral @Word32 @Int64 i
encodeVarBindResult (ArbitraryVal bs) = Value Application 4 $ OctetString bs
encodeVarBindResult (BigCounterVal i) = Value Application 6 $ Integer $ fromIntegral @Word64 @Int64 i
encodeVarBindResult Unspecified = Value Universal 5 Null
encodeVarBindResult NoSuchObject = Value ContextSpecific 0 Null
encodeVarBindResult NoSuchInstance = Value ContextSpecific 1 Null
encodeVarBindResult EndOfMibView = Value ContextSpecific 2 Null

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

newtype AuthProtocol = AuthProtocol Word8
  deriving newtype Eq

pattern NoAuthProtocol :: AuthProtocol
pattern NoAuthProtocol = AuthProtocol 1

pattern HmacMd5AuthProtocol :: AuthProtocol
pattern HmacMd5AuthProtocol = AuthProtocol 2

pattern HmacShaAuthProtocol :: AuthProtocol
pattern HmacShaAuthProtocol = AuthProtocol 3

pattern HmacSha256AuthProtocol :: AuthProtocol
pattern HmacSha256AuthProtocol = AuthProtocol 6

pattern HmacSha512AuthProtocol :: AuthProtocol
pattern HmacSha512AuthProtocol = AuthProtocol 7

-- | Note: The extended privacy protocols like AES256 are not in the
-- same namespace as DES. We cannot add AES128 without changing how
-- this is done. I am not worried about this for now.
newtype PrivProtocol = PrivProtocol Word8
  deriving newtype Eq

pattern NoPrivProtocol :: PrivProtocol
pattern NoPrivProtocol = PrivProtocol 1

pattern DesPrivProtocol :: PrivProtocol
pattern DesPrivProtocol = PrivProtocol 2

pattern AesPrivProtocol :: PrivProtocol
pattern AesPrivProtocol = PrivProtocol 4

pattern Aes256PrivProtocol :: PrivProtocol
pattern Aes256PrivProtocol = PrivProtocol 104

data ScopedPduData
  = ScopedPduDataPlaintext !ScopedPdu
  | ScopedPduDataEncrypted {-# UNPACK #-} !Bytes

data ScopedPdu = ScopedPdu
  { contextEngineId :: {-# UNPACK #-} !Bytes
  , contextName :: {-# UNPACK #-} !Bytes
  , data_ :: !Pdus
    -- ^ In the RFC, this has type @ANY@. However, the only type this ever
    -- has in practice is @PDUs@. Suffixed with underscore because @data@
    -- is reserved Haskell identifier.
  } deriving stock (Eq,Show)

encodeScopedPdu :: ScopedPdu -> Asn.Value
encodeScopedPdu ScopedPdu{contextEngineId,contextName,data_} =
  Value Universal 16 $ Constructed $ C.tripleton
    (Value Universal 4 $ OctetString contextEngineId)
    (Value Universal 4 $ OctetString contextName)
    (encodePdus data_)

data SecurityParameters = SecurityParameters
  { authoritativeEngineId :: {-# UNPACK #-} !Bytes
  , authoritativeEngineBoots :: !Int32
    -- ^ Should not be negative.
  , authoritativeEngineTime :: !Int32
    -- ^ Should not be negative.
  , userName :: {-# UNPACK #-} !Bytes
  , authenticationParameters :: {-# UNPACK #-} !Bytes
  , privacyParameters :: {-# UNPACK #-} !Bytes
  }

encodeSecurityParameters :: SecurityParameters -> Asn.Value
encodeSecurityParameters SecurityParameters
    {authoritativeEngineId,authoritativeEngineBoots,authoritativeEngineTime
    ,userName,authenticationParameters,privacyParameters} =
  Value Universal 16 $ Constructed $ smallArrayFromListN 6
    [ Value Universal 4 $ OctetString authoritativeEngineId
    , Value Universal 2 $ Integer (fromIntegral @Int32 @Int64 authoritativeEngineBoots)
    , Value Universal 2 $ Integer (fromIntegral @Int32 @Int64 authoritativeEngineTime)
    , Value Universal 4 $ OctetString userName
    , Value Universal 4 $ OctetString authenticationParameters
    , Value Universal 4 $ OctetString privacyParameters
    ]

data HeaderData = HeaderData
  { id :: !Int32
  , maxSize :: !Int32
  , flags :: !Word8
    -- ^ An octet string with length 1. This is not serialized as an integer.
  , securityModel :: !Int32
  }

encodeHeaderData :: HeaderData -> Asn.Value
encodeHeaderData HeaderData{id,maxSize,flags,securityModel} =
  Value Universal 16 $ Constructed $ C.quadrupleton
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 id)
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 maxSize)
    (Value Universal 4 $ OctetString $ Bytes.singleton flags)
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 securityModel)

data MessageV3 = MessageV3
  { version :: !Int32
    -- ^ Should be set to 3.
  , globalData :: !HeaderData
  , securityParameters :: {-# UNPACK #-} !Bytes
    -- ^ This is an DER-encoded 'SecurityParameters'. Perhaps the greatest
    -- failing of SNMPv3 is that, in the name of extensibility, the
    -- authors decided to include an encoded object as a field of another
    -- object. History tells us that this extensibility was unneeded,
    -- but a younger generation must now shoulder this burden.
  , data_ :: !ScopedPduData
  }

encodeMessageV3 :: MessageV3 -> Asn.Value
encodeMessageV3 MessageV3{version,globalData,securityParameters,data_} =
  Value Universal 16 $ Constructed $ C.quadrupleton
    (Value Universal 2 $ Integer $ fromIntegral @Int32 @Int64 version)
    (encodeHeaderData globalData)
    (Value Universal 4 $ OctetString securityParameters)
    (encodeScopedPduData data_)

encodeScopedPduData :: ScopedPduData -> Asn.Value
encodeScopedPduData (ScopedPduDataPlaintext spdu) = encodeScopedPdu spdu
encodeScopedPduData (ScopedPduDataEncrypted bs) = Value Universal 4 (OctetString bs)
