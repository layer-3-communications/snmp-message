# snmp-message

This repository provides SNMP message encoding and decoding.
Simple Network Management Protocol (SNMP) is an Internet Standard protocol
for collecting and organizing information about managed devices on IP networks
and for modifying that information to change device behavior.

## IETF RFCs

Relevant definitions are copied from RFCs for reference. Several fields are
omitted or abridged for clarity.

### RFC3412

SNMPv3 message type, headers, and PDUs:

    SNMPv3Message ::= SEQUENCE {
        -- identify the layout of the SNMPv3Message
        -- this element is in same position as in SNMPv1
        -- and SNMPv2c, allowing recognition
        -- the value 3 is used for snmpv3
        msgVersion INTEGER ( 0 .. 2147483647 ),
        -- administrative parameters
        msgGlobalData HeaderData,
        -- security model-specific parameters
        -- format defined by Security Model
        msgSecurityParameters OCTET STRING,
        msgData  ScopedPduData
    }
    HeaderData ::= SEQUENCE {
        msgID      INTEGER (0..2147483647),
        msgMaxSize INTEGER (484..2147483647),
        msgFlags   OCTET STRING (SIZE(1)),
                   --  .... ...1   authFlag
                   --  .... ..1.   privFlag
                   --  .... .1..   reportableFlag
                   --              Please observe:
                   --  .... ..00   is OK, means noAuthNoPriv
                   --  .... ..01   is OK, means authNoPriv
                   --  .... ..10   reserved, MUST NOT be used.
                   --  .... ..11   is OK, means authPriv
        msgSecurityModel INTEGER (1..2147483647)
    }
    ScopedPduData ::= CHOICE {
        plaintext    ScopedPDU,
        encryptedPDU OCTET STRING  -- encrypted scopedPDU value
    }
    ScopedPDU ::= SEQUENCE {
        contextEngineID  OCTET STRING,
        contextName      OCTET STRING,
        data             ANY -- e.g., PDUs as defined in [RFC3416]
    }

### RFC3414

SNMPv3 `auth` and `priv` types:

    usmNoAuthProtocol OBJECT-IDENTITY
        STATUS        current
        DESCRIPTION  "No Authentication Protocol."
        ::= { snmpAuthProtocols 1 }
    usmHMACMD5AuthProtocol OBJECT-IDENTITY
        STATUS        current
        DESCRIPTION  "The HMAC-MD5-96 Digest Authentication Protocol."
        REFERENCE    "..."
        ::= { snmpAuthProtocols 2 }
    usmHMACSHAAuthProtocol OBJECT-IDENTITY
        STATUS        current
        DESCRIPTION  "The HMAC-SHA-96 Digest Authentication Protocol."
        REFERENCE    "..."
        ::= { snmpAuthProtocols 3 }
    usmNoPrivProtocol OBJECT-IDENTITY
        STATUS        current
        DESCRIPTION  "No Privacy Protocol."
        ::= { snmpPrivProtocols 1 }
    usmDESPrivProtocol OBJECT-IDENTITY
        STATUS        current
        DESCRIPTION  "The CBC-DES Symmetric Encryption Protocol."
        REFERENCE    "..."
        ::= { snmpPrivProtocols 2 }

SNMPv3 USM security parameters:

    UsmSecurityParameters ::=
        SEQUENCE {
         -- global User-based security parameters
            msgAuthoritativeEngineID     OCTET STRING,
            msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
            msgAuthoritativeEngineTime   INTEGER (0..2147483647),
            msgUserName                  OCTET STRING (SIZE(0..32)),
         -- authentication protocol specific parameters
            msgAuthenticationParameters  OCTET STRING,
         -- privacy protocol specific parameters
            msgPrivacyParameters         OCTET STRING
