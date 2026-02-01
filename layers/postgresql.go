// Copyright 2026 Kubeshark Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kubeshark/gopacket"
)

// PostgreSQL message type constants for frontend (client) messages
const (
	PGFrontendBind        byte = 'B' // Bind parameters to prepared statement
	PGFrontendClose       byte = 'C' // Close prepared statement or portal
	PGFrontendCopyData    byte = 'd' // COPY data
	PGFrontendCopyDone    byte = 'c' // COPY done
	PGFrontendCopyFail    byte = 'f' // COPY failed
	PGFrontendDescribe    byte = 'D' // Describe prepared statement or portal
	PGFrontendExecute     byte = 'E' // Execute portal
	PGFrontendFlush       byte = 'H' // Flush
	PGFrontendFunctionCall byte = 'F' // Function call (deprecated)
	PGFrontendParse       byte = 'P' // Parse query into prepared statement
	PGFrontendPassword    byte = 'p' // Password response
	PGFrontendQuery       byte = 'Q' // Simple query
	PGFrontendSync        byte = 'S' // Sync (end of extended query)
	PGFrontendTerminate   byte = 'X' // Terminate connection
)

// PostgreSQL message type constants for backend (server) messages
const (
	PGBackendAuth              byte = 'R' // Authentication request/response
	PGBackendBackendKeyData    byte = 'K' // Backend key data (for cancel)
	PGBackendBindComplete      byte = '2' // Bind complete
	PGBackendCloseComplete     byte = '3' // Close complete
	PGBackendCommandComplete   byte = 'C' // Command complete
	PGBackendCopyData          byte = 'd' // COPY data
	PGBackendCopyDone          byte = 'c' // COPY done
	PGBackendCopyInResponse    byte = 'G' // COPY IN response
	PGBackendCopyOutResponse   byte = 'H' // COPY OUT response
	PGBackendCopyBothResponse  byte = 'W' // COPY BOTH response
	PGBackendDataRow           byte = 'D' // Data row
	PGBackendEmptyQueryResponse byte = 'I' // Empty query response
	PGBackendErrorResponse     byte = 'E' // Error response
	PGBackendFunctionCallResp  byte = 'V' // Function call response
	PGBackendNoData            byte = 'n' // No data
	PGBackendNoticeResponse    byte = 'N' // Notice response
	PGBackendNotificationResp  byte = 'A' // Notification response
	PGBackendParameterDesc     byte = 't' // Parameter description
	PGBackendParameterStatus   byte = 'S' // Parameter status
	PGBackendParseComplete     byte = '1' // Parse complete
	PGBackendPortalSuspended   byte = 's' // Portal suspended
	PGBackendReadyForQuery     byte = 'Z' // Ready for query
	PGBackendRowDescription    byte = 'T' // Row description
)

// Special protocol codes (no message type byte)
const (
	PGProtocolVersion3  uint32 = 196608   // Protocol version 3.0 (3 << 16)
	PGSSLRequestCode    uint32 = 80877103 // SSL request magic number
	PGCancelRequestCode uint32 = 80877102 // Cancel request magic number
	PGGSSENCRequestCode uint32 = 80877104 // GSSAPI encryption request
)

// PGTransactionStatus represents the current transaction state
type PGTransactionStatus byte

const (
	PGTransactionIdle      PGTransactionStatus = 'I' // Not in a transaction
	PGTransactionActive    PGTransactionStatus = 'T' // In a transaction
	PGTransactionFailed    PGTransactionStatus = 'E' // In a failed transaction
)

func (s PGTransactionStatus) String() string {
	switch s {
	case PGTransactionIdle:
		return "Idle"
	case PGTransactionActive:
		return "InTransaction"
	case PGTransactionFailed:
		return "FailedTransaction"
	default:
		return fmt.Sprintf("Unknown(%c)", s)
	}
}

// PGMessageType represents a PostgreSQL message type
type PGMessageType byte

// String returns a string representation of the message type.
// Note: Some message types share the same byte value but have different meanings
// for frontend vs backend. Use StringWithDirection for direction-aware output.
func (m PGMessageType) String() string {
	// Return commonly used names, preferring backend interpretation for shared codes
	switch byte(m) {
	case 'B':
		return "Bind"
	case 'C':
		return "Close/CommandComplete"
	case 'D':
		return "Describe/DataRow"
	case 'E':
		return "Execute/ErrorResponse"
	case 'F':
		return "FunctionCall"
	case 'H':
		return "Flush/CopyOutResponse"
	case 'P':
		return "Parse"
	case 'p':
		return "Password"
	case 'Q':
		return "Query"
	case 'S':
		return "Sync/ParameterStatus"
	case 'X':
		return "Terminate"
	case 'R':
		return "Authentication"
	case 'K':
		return "BackendKeyData"
	case '2':
		return "BindComplete"
	case '3':
		return "CloseComplete"
	case 'G':
		return "CopyInResponse"
	case 'W':
		return "CopyBothResponse"
	case 'I':
		return "EmptyQueryResponse"
	case 'n':
		return "NoData"
	case 'N':
		return "NoticeResponse"
	case 'A':
		return "NotificationResponse"
	case 't':
		return "ParameterDescription"
	case '1':
		return "ParseComplete"
	case 's':
		return "PortalSuspended"
	case 'Z':
		return "ReadyForQuery"
	case 'T':
		return "RowDescription"
	case 'd':
		return "CopyData"
	case 'c':
		return "CopyDone"
	case 'f':
		return "CopyFail"
	case 'V':
		return "FunctionCallResponse"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", byte(m))
	}
}

// FrontendString returns the frontend interpretation of the message type
func (m PGMessageType) FrontendString() string {
	switch byte(m) {
	case 'B':
		return "Bind"
	case 'C':
		return "Close"
	case 'D':
		return "Describe"
	case 'E':
		return "Execute"
	case 'F':
		return "FunctionCall"
	case 'H':
		return "Flush"
	case 'P':
		return "Parse"
	case 'p':
		return "Password"
	case 'Q':
		return "Query"
	case 'S':
		return "Sync"
	case 'X':
		return "Terminate"
	case 'd':
		return "CopyData"
	case 'c':
		return "CopyDone"
	case 'f':
		return "CopyFail"
	default:
		return fmt.Sprintf("Frontend(0x%02x)", byte(m))
	}
}

// BackendString returns the backend interpretation of the message type
func (m PGMessageType) BackendString() string {
	switch byte(m) {
	case 'R':
		return "Authentication"
	case 'K':
		return "BackendKeyData"
	case '2':
		return "BindComplete"
	case '3':
		return "CloseComplete"
	case 'C':
		return "CommandComplete"
	case 'D':
		return "DataRow"
	case 'I':
		return "EmptyQueryResponse"
	case 'E':
		return "ErrorResponse"
	case 'V':
		return "FunctionCallResponse"
	case 'G':
		return "CopyInResponse"
	case 'H':
		return "CopyOutResponse"
	case 'W':
		return "CopyBothResponse"
	case 'n':
		return "NoData"
	case 'N':
		return "NoticeResponse"
	case 'A':
		return "NotificationResponse"
	case 't':
		return "ParameterDescription"
	case 'S':
		return "ParameterStatus"
	case '1':
		return "ParseComplete"
	case 's':
		return "PortalSuspended"
	case 'Z':
		return "ReadyForQuery"
	case 'T':
		return "RowDescription"
	case 'd':
		return "CopyData"
	case 'c':
		return "CopyDone"
	default:
		return fmt.Sprintf("Backend(0x%02x)", m)
	}
}

// PGColumn represents a column from RowDescription
type PGColumn struct {
	Name         string // Column name
	TableOID     uint32 // OID of the table (0 if not a table column)
	ColumnAttr   uint16 // Attribute number of the column (0 if not a table column)
	TypeOID      uint32 // OID of the column's data type
	TypeSize     int16  // Data type size (negative for variable-width)
	TypeModifier int32  // Type modifier (e.g., precision/scale)
	Format       uint16 // Format code: 0=text, 1=binary
}

// PGValue represents a single column value from a DataRow
type PGValue struct {
	IsNull bool   // True if value is NULL (-1 length)
	Data   []byte // Raw bytes (text or binary format)
}

// PostgreSQL is the layer for PostgreSQL wire protocol (pgwire) messages.
type PostgreSQL struct {
	BaseLayer

	// Message framing
	IsStartupPhase bool            // True for startup/SSL messages (no type byte)
	IsSSLRequest   bool            // True if this is an SSLRequest
	IsSSLResponse  bool            // True if this is an SSL response ('S' or 'N')
	SSLWilling     bool            // True if server is willing to use SSL
	IsRequest      bool            // Direction: true = frontend->backend
	MessageType    PGMessageType   // 'Q', 'D', 'E', etc.
	Length         uint32          // Message length (includes length field)

	// Startup message data
	ProtocolVersion uint32            // Protocol version (usually 196608 for v3.0)
	StartupParams   map[string]string // Startup parameters (user, database, etc.)

	// Simple Query (frontend 'Q')
	Query string // SQL query text

	// Extended Query Protocol
	// Parse (frontend 'P')
	ParsedStmt   string   // Prepared statement name (empty for unnamed)
	ParsedQuery  string   // Query string
	ParamTypeOIDs []uint32 // Parameter type OIDs (from Parse)

	// Bind (frontend 'B')
	Portal          string    // Destination portal name
	SourceStmt      string    // Source prepared statement name
	ParameterValues [][]byte  // Parameter values (raw bytes)
	ResultFormats   []uint16  // Result column format codes

	// Execute (frontend 'E')
	ExecutePortal   string // Portal name to execute
	MaxRows         uint32 // Max rows to return (0 = unlimited)

	// Describe (frontend 'D')
	DescribeType   byte   // 'S' for statement, 'P' for portal
	DescribeName   string // Name of statement/portal

	// Close (frontend 'C')
	CloseType byte   // 'S' for statement, 'P' for portal
	CloseName string // Name of statement/portal

	// RowDescription (backend 'T')
	Columns []PGColumn // Column definitions

	// DataRow (backend 'D')
	Rows [][]PGValue // All row values (full capture)

	// CommandComplete (backend 'C')
	CommandTag string // e.g., "SELECT 5", "INSERT 0 1"

	// ErrorResponse/NoticeResponse (backend 'E'/'N')
	ErrorSeverity string          // Severity: ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG, INFO, LOG
	ErrorCode     string          // SQLSTATE code (5 chars)
	ErrorMessage  string          // Primary error message
	ErrorFields   map[byte]string // All error/notice fields

	// ReadyForQuery (backend 'Z')
	TransactionStatus PGTransactionStatus

	// ParameterStatus (backend 'S')
	ParamName  string // Parameter name
	ParamValue string // Parameter value

	// BackendKeyData (backend 'K')
	ProcessID uint32 // Backend process ID
	SecretKey uint32 // Secret key for cancel requests

	// Authentication (backend 'R')
	AuthType uint32 // Authentication type
	AuthData []byte // Additional auth data (e.g., salt)

	// NotificationResponse (backend 'A')
	NotifyPID     uint32 // Notifying backend PID
	NotifyChannel string // Channel name
	NotifyPayload string // Payload string
}

// LayerType returns LayerTypePostgreSQL
func (p *PostgreSQL) LayerType() gopacket.LayerType {
	return LayerTypePostgreSQL
}

// CanDecode returns the set of layer types this decoder can decode
func (p *PostgreSQL) CanDecode() gopacket.LayerClass {
	return LayerTypePostgreSQL
}

// NextLayerType returns the layer type of the next layer
func (p *PostgreSQL) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns the application layer payload (implements ApplicationLayer)
func (p *PostgreSQL) Payload() []byte {
	return p.BaseLayer.Payload
}

var (
	errPostgreSQLTooShort       = errors.New("PostgreSQL message too short")
	errPostgreSQLInvalidLength  = errors.New("PostgreSQL message length invalid")
	errPostgreSQLTruncated      = errors.New("PostgreSQL message truncated")
)

// DecodeFromBytes decodes the given bytes into this layer
func (p *PostgreSQL) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		return errPostgreSQLTooShort
	}

	// Reset fields
	p.IsStartupPhase = false
	p.IsSSLRequest = false
	p.IsSSLResponse = false
	p.SSLWilling = false
	p.StartupParams = nil
	p.Query = ""
	p.ParsedStmt = ""
	p.ParsedQuery = ""
	p.ParamTypeOIDs = nil
	p.Portal = ""
	p.SourceStmt = ""
	p.ParameterValues = nil
	p.ResultFormats = nil
	p.ExecutePortal = ""
	p.MaxRows = 0
	p.DescribeType = 0
	p.DescribeName = ""
	p.CloseType = 0
	p.CloseName = ""
	p.Columns = nil
	p.Rows = nil
	p.CommandTag = ""
	p.ErrorSeverity = ""
	p.ErrorCode = ""
	p.ErrorMessage = ""
	p.ErrorFields = nil
	p.TransactionStatus = 0
	p.ParamName = ""
	p.ParamValue = ""
	p.ProcessID = 0
	p.SecretKey = 0
	p.AuthType = 0
	p.AuthData = nil
	p.NotifyPID = 0
	p.NotifyChannel = ""
	p.NotifyPayload = ""

	// Check for single-byte SSL response
	if len(data) == 1 && (data[0] == 'S' || data[0] == 'N') {
		p.IsSSLResponse = true
		p.SSLWilling = data[0] == 'S'
		p.BaseLayer = BaseLayer{Contents: data[:1], Payload: nil}
		return nil
	}

	// Check if this might be a startup-phase message (no type byte)
	// Startup messages start with 4-byte length
	if len(data) >= 8 {
		length := binary.BigEndian.Uint32(data[0:4])
		code := binary.BigEndian.Uint32(data[4:8])

		// Check for SSLRequest
		if length == 8 && code == PGSSLRequestCode {
			p.IsStartupPhase = true
			p.IsSSLRequest = true
			p.IsRequest = true
			p.Length = length
			p.BaseLayer = BaseLayer{Contents: data[:8], Payload: data[8:]}
			return nil
		}

		// Check for CancelRequest
		if length == 16 && code == PGCancelRequestCode {
			p.IsStartupPhase = true
			p.IsRequest = true
			p.Length = length
			if len(data) >= 16 {
				p.ProcessID = binary.BigEndian.Uint32(data[8:12])
				p.SecretKey = binary.BigEndian.Uint32(data[12:16])
				p.BaseLayer = BaseLayer{Contents: data[:16], Payload: data[16:]}
			}
			return nil
		}

		// Check for GSSENCRequest
		if length == 8 && code == PGGSSENCRequestCode {
			p.IsStartupPhase = true
			p.IsRequest = true
			p.Length = length
			p.BaseLayer = BaseLayer{Contents: data[:8], Payload: data[8:]}
			return nil
		}

		// Check for StartupMessage (protocol version 3.0)
		if code == PGProtocolVersion3 && length >= 8 && int(length) <= len(data) {
			p.IsStartupPhase = true
			p.IsRequest = true
			p.Length = length
			p.ProtocolVersion = code
			p.StartupParams = make(map[string]string)

			// Parse null-terminated key-value pairs
			offset := 8
			for offset < int(length)-1 {
				// Read key
				keyEnd := offset
				for keyEnd < int(length) && data[keyEnd] != 0 {
					keyEnd++
				}
				if keyEnd >= int(length) {
					break
				}
				key := string(data[offset:keyEnd])
				offset = keyEnd + 1

				if key == "" {
					break // End of parameters
				}

				// Read value
				valEnd := offset
				for valEnd < int(length) && data[valEnd] != 0 {
					valEnd++
				}
				value := string(data[offset:valEnd])
				offset = valEnd + 1

				p.StartupParams[key] = value
			}

			msgLen := int(length)
			if msgLen > len(data) {
				msgLen = len(data)
			}
			p.BaseLayer = BaseLayer{Contents: data[:msgLen], Payload: data[msgLen:]}
			return nil
		}
	}

	// Regular message format: type (1 byte) + length (4 bytes) + payload
	if len(data) < 5 {
		return errPostgreSQLTooShort
	}

	p.MessageType = PGMessageType(data[0])
	p.Length = binary.BigEndian.Uint32(data[1:5])

	// Length includes the length field itself but not the type byte
	totalLen := int(p.Length) + 1
	if p.Length < 4 {
		return errPostgreSQLInvalidLength
	}

	// Determine if this is a request or response based on message type
	// Frontend-only message types: B, Q, P, X, p, F
	// (These bytes are not used by backend messages)
	// Shared bytes: C, D, E, H, S (have different meanings for frontend/backend)
	// Note: This heuristic works for unambiguous cases. For ambiguous messages,
	// stream-level context would be needed for accurate direction detection.
	// If IsRequest was set before calling DecodeFromBytes (e.g., by tcpassembly),
	// we preserve it for ambiguous messages.
	switch byte(p.MessageType) {
	case 'B', // Bind (frontend only)
		'Q', // Query (frontend only)
		'P', // Parse (frontend only)
		'X', // Terminate (frontend only)
		'p', // Password (frontend only)
		'F': // FunctionCall (frontend only)
		p.IsRequest = true
	case 'C', 'D', 'E', 'H', 'S':
		// Ambiguous - shared between frontend and backend
		// Preserve IsRequest if already set (e.g., from stream context),
		// otherwise default to false (backend)
		// The IsRequest field can be set before calling DecodeFromBytes
		// to provide direction hint from tcpassembly or similar.
	default:
		// All other message types are backend-only
		p.IsRequest = false
	}

	// Check if we have enough data
	if len(data) < totalLen {
		// Partial message - decode what we can
		df.SetTruncated()
		p.BaseLayer = BaseLayer{Contents: data, Payload: nil}
		return errPostgreSQLTruncated
	}

	payload := data[5:totalLen]
	p.BaseLayer = BaseLayer{Contents: data[:totalLen], Payload: data[totalLen:]}

	// Parse message-specific content
	// Note: Some message type bytes are shared between frontend and backend,
	// so we use IsRequest to determine which decoder to use.
	msgByte := byte(p.MessageType)
	if p.IsRequest {
		// Frontend (client) messages
		switch msgByte {
		case 'Q': // Query
			p.decodeQuery(payload)
		case 'P': // Parse
			p.decodeParse(payload)
		case 'B': // Bind
			p.decodeBind(payload)
		case 'E': // Execute
			p.decodeExecute(payload)
		case 'D': // Describe
			p.decodeDescribe(payload)
		case 'C': // Close
			p.decodeClose(payload)
		}
	} else {
		// Backend (server) messages
		switch msgByte {
		case 'T': // RowDescription
			p.decodeRowDescription(payload)
		case 'D': // DataRow
			p.decodeDataRow(payload)
		case 'C': // CommandComplete
			p.decodeCommandComplete(payload)
		case 'E', 'N': // ErrorResponse, NoticeResponse
			p.decodeErrorResponse(payload)
		case 'Z': // ReadyForQuery
			p.decodeReadyForQuery(payload)
		case 'S': // ParameterStatus
			p.decodeParameterStatus(payload)
		case 'K': // BackendKeyData
			p.decodeBackendKeyData(payload)
		case 'R': // Authentication
			p.decodeAuth(payload)
		case 'A': // NotificationResponse
			p.decodeNotification(payload)
		case 't': // ParameterDescription
			p.decodeParameterDescription(payload)
		}
	}

	return nil
}

// decodeQuery parses a simple query message
func (p *PostgreSQL) decodeQuery(data []byte) {
	// Query is null-terminated string
	p.Query = cstring(data)
}

// decodeParse parses a Parse message (extended query protocol)
func (p *PostgreSQL) decodeParse(data []byte) {
	offset := 0

	// Prepared statement name (null-terminated)
	p.ParsedStmt, offset = readCString(data, offset)
	if offset < 0 {
		return
	}

	// Query string (null-terminated)
	p.ParsedQuery, offset = readCString(data, offset)
	if offset < 0 {
		return
	}

	// Number of parameter type OIDs
	if offset+2 > len(data) {
		return
	}
	numParams := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Parameter type OIDs
	p.ParamTypeOIDs = make([]uint32, 0, numParams)
	for i := 0; i < numParams && offset+4 <= len(data); i++ {
		oid := binary.BigEndian.Uint32(data[offset : offset+4])
		p.ParamTypeOIDs = append(p.ParamTypeOIDs, oid)
		offset += 4
	}
}

// decodeBind parses a Bind message
func (p *PostgreSQL) decodeBind(data []byte) {
	offset := 0

	// Destination portal name
	p.Portal, offset = readCString(data, offset)
	if offset < 0 {
		return
	}

	// Source prepared statement name
	p.SourceStmt, offset = readCString(data, offset)
	if offset < 0 {
		return
	}

	// Number of parameter format codes
	if offset+2 > len(data) {
		return
	}
	numFormatCodes := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Skip format codes (we don't store them separately)
	offset += numFormatCodes * 2
	if offset > len(data) {
		return
	}

	// Number of parameter values
	if offset+2 > len(data) {
		return
	}
	numParams := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Parameter values
	p.ParameterValues = make([][]byte, 0, numParams)
	for i := 0; i < numParams; i++ {
		if offset+4 > len(data) {
			return
		}
		valLen := int(int32(binary.BigEndian.Uint32(data[offset : offset+4])))
		offset += 4

		if valLen == -1 {
			// NULL value
			p.ParameterValues = append(p.ParameterValues, nil)
		} else if valLen >= 0 {
			if offset+valLen > len(data) {
				return
			}
			val := make([]byte, valLen)
			copy(val, data[offset:offset+valLen])
			p.ParameterValues = append(p.ParameterValues, val)
			offset += valLen
		}
	}

	// Result format codes
	if offset+2 > len(data) {
		return
	}
	numResultFormats := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	p.ResultFormats = make([]uint16, 0, numResultFormats)
	for i := 0; i < numResultFormats && offset+2 <= len(data); i++ {
		format := binary.BigEndian.Uint16(data[offset : offset+2])
		p.ResultFormats = append(p.ResultFormats, format)
		offset += 2
	}
}

// decodeExecute parses an Execute message
func (p *PostgreSQL) decodeExecute(data []byte) {
	offset := 0

	// Portal name
	p.ExecutePortal, offset = readCString(data, offset)
	if offset < 0 || offset+4 > len(data) {
		return
	}

	// Max rows
	p.MaxRows = binary.BigEndian.Uint32(data[offset : offset+4])
}

// decodeDescribe parses a Describe message
func (p *PostgreSQL) decodeDescribe(data []byte) {
	if len(data) < 1 {
		return
	}
	p.DescribeType = data[0]
	p.DescribeName, _ = readCString(data, 1)
}

// decodeClose parses a Close message
func (p *PostgreSQL) decodeClose(data []byte) {
	if len(data) < 1 {
		return
	}
	p.CloseType = data[0]
	p.CloseName, _ = readCString(data, 1)
}

// decodeRowDescription parses a RowDescription message
func (p *PostgreSQL) decodeRowDescription(data []byte) {
	if len(data) < 2 {
		return
	}

	numFields := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2

	p.Columns = make([]PGColumn, 0, numFields)
	for i := 0; i < numFields; i++ {
		var col PGColumn

		// Column name (null-terminated)
		col.Name, offset = readCString(data, offset)
		if offset < 0 {
			return
		}

		// Need at least 18 bytes for the fixed fields
		if offset+18 > len(data) {
			return
		}

		col.TableOID = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		col.ColumnAttr = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		col.TypeOID = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		col.TypeSize = int16(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		col.TypeModifier = int32(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4

		col.Format = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		p.Columns = append(p.Columns, col)
	}
}

// decodeDataRow parses a DataRow message
func (p *PostgreSQL) decodeDataRow(data []byte) {
	if len(data) < 2 {
		return
	}

	numCols := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2

	row := make([]PGValue, 0, numCols)
	for i := 0; i < numCols; i++ {
		if offset+4 > len(data) {
			return
		}

		valLen := int(int32(binary.BigEndian.Uint32(data[offset : offset+4])))
		offset += 4

		var val PGValue
		if valLen == -1 {
			val.IsNull = true
		} else if valLen >= 0 {
			if offset+valLen > len(data) {
				return
			}
			val.Data = make([]byte, valLen)
			copy(val.Data, data[offset:offset+valLen])
			offset += valLen
		}
		row = append(row, val)
	}

	// Append to existing rows (for stream accumulation)
	p.Rows = append(p.Rows, row)
}

// decodeCommandComplete parses a CommandComplete message
func (p *PostgreSQL) decodeCommandComplete(data []byte) {
	p.CommandTag = cstring(data)
}

// decodeErrorResponse parses an ErrorResponse or NoticeResponse message
func (p *PostgreSQL) decodeErrorResponse(data []byte) {
	p.ErrorFields = make(map[byte]string)
	offset := 0

	for offset < len(data) {
		if data[offset] == 0 {
			break // End of fields
		}

		fieldType := data[offset]
		offset++

		value, newOffset := readCString(data, offset)
		if newOffset < 0 {
			return
		}
		offset = newOffset

		p.ErrorFields[fieldType] = value

		switch fieldType {
		case 'S', 'V': // Severity (localized and non-localized)
			if p.ErrorSeverity == "" {
				p.ErrorSeverity = value
			}
		case 'C': // SQLSTATE code
			p.ErrorCode = value
		case 'M': // Message
			p.ErrorMessage = value
		}
	}
}

// decodeReadyForQuery parses a ReadyForQuery message
func (p *PostgreSQL) decodeReadyForQuery(data []byte) {
	if len(data) >= 1 {
		p.TransactionStatus = PGTransactionStatus(data[0])
	}
}

// decodeParameterStatus parses a ParameterStatus message
func (p *PostgreSQL) decodeParameterStatus(data []byte) {
	offset := 0
	p.ParamName, offset = readCString(data, offset)
	if offset >= 0 {
		p.ParamValue, _ = readCString(data, offset)
	}
}

// decodeBackendKeyData parses a BackendKeyData message
func (p *PostgreSQL) decodeBackendKeyData(data []byte) {
	if len(data) >= 8 {
		p.ProcessID = binary.BigEndian.Uint32(data[0:4])
		p.SecretKey = binary.BigEndian.Uint32(data[4:8])
	}
}

// decodeAuth parses an Authentication message
func (p *PostgreSQL) decodeAuth(data []byte) {
	if len(data) >= 4 {
		p.AuthType = binary.BigEndian.Uint32(data[0:4])
		if len(data) > 4 {
			p.AuthData = make([]byte, len(data)-4)
			copy(p.AuthData, data[4:])
		}
	}
}

// decodeNotification parses a NotificationResponse message
func (p *PostgreSQL) decodeNotification(data []byte) {
	if len(data) < 4 {
		return
	}
	p.NotifyPID = binary.BigEndian.Uint32(data[0:4])
	offset := 4
	p.NotifyChannel, offset = readCString(data, offset)
	if offset >= 0 {
		p.NotifyPayload, _ = readCString(data, offset)
	}
}

// decodeParameterDescription parses a ParameterDescription message
func (p *PostgreSQL) decodeParameterDescription(data []byte) {
	if len(data) < 2 {
		return
	}
	numParams := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2

	p.ParamTypeOIDs = make([]uint32, 0, numParams)
	for i := 0; i < numParams && offset+4 <= len(data); i++ {
		oid := binary.BigEndian.Uint32(data[offset : offset+4])
		p.ParamTypeOIDs = append(p.ParamTypeOIDs, oid)
		offset += 4
	}
}

// cstring extracts a null-terminated string from data
func cstring(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// readCString reads a null-terminated string starting at offset
// Returns the string and the offset after the null terminator
// Returns -1 for offset if string is not properly terminated
func readCString(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", -1
	}
	for i := offset; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[offset:i]), i + 1
		}
	}
	// Not null-terminated, return what we have
	return string(data[offset:]), -1
}

// decodePostgreSQL is the decoder function for PostgreSQL layer
func decodePostgreSQL(data []byte, p gopacket.PacketBuilder) error {
	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(pg)
	p.SetApplicationLayer(pg)
	return nil
}
