// Copyright 2026 Kubeshark Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kubeshark/gopacket"
)

// Helper to create a PostgreSQL message with type byte
func makeMessage(msgType byte, payload []byte) []byte {
	msg := make([]byte, 1+4+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload))) // length includes itself
	copy(msg[5:], payload)
	return msg
}

// Helper to create a null-terminated string
func cstr(s string) []byte {
	return append([]byte(s), 0)
}

func TestPostgreSQLSSLRequest(t *testing.T) {
	// SSLRequest: length=8, code=80877103
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 8)
	binary.BigEndian.PutUint32(data[4:8], PGSSLRequestCode)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode SSLRequest: %v", err)
	}

	if !pg.IsStartupPhase {
		t.Error("Expected IsStartupPhase to be true")
	}
	if !pg.IsSSLRequest {
		t.Error("Expected IsSSLRequest to be true")
	}
	if !pg.IsRequest {
		t.Error("Expected IsRequest to be true")
	}
}

func TestPostgreSQLSSLResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		willing  bool
	}{
		{"Willing", []byte{'S'}, true},
		{"NotWilling", []byte{'N'}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pg := &PostgreSQL{}
			err := pg.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback)
			if err != nil {
				t.Fatalf("Failed to decode SSL response: %v", err)
			}

			if !pg.IsSSLResponse {
				t.Error("Expected IsSSLResponse to be true")
			}
			if pg.SSLWilling != tt.willing {
				t.Errorf("Expected SSLWilling=%v, got %v", tt.willing, pg.SSLWilling)
			}
		})
	}
}

func TestPostgreSQLStartupMessage(t *testing.T) {
	// Build startup message
	params := []byte{}
	params = append(params, cstr("user")...)
	params = append(params, cstr("testuser")...)
	params = append(params, cstr("database")...)
	params = append(params, cstr("testdb")...)
	params = append(params, 0) // terminal null

	data := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(data[0:4], uint32(8+len(params)))
	binary.BigEndian.PutUint32(data[4:8], PGProtocolVersion3)
	copy(data[8:], params)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode StartupMessage: %v", err)
	}

	if !pg.IsStartupPhase {
		t.Error("Expected IsStartupPhase to be true")
	}
	if !pg.IsRequest {
		t.Error("Expected IsRequest to be true")
	}
	if pg.ProtocolVersion != PGProtocolVersion3 {
		t.Errorf("Expected protocol version %d, got %d", PGProtocolVersion3, pg.ProtocolVersion)
	}
	if pg.StartupParams["user"] != "testuser" {
		t.Errorf("Expected user=testuser, got %s", pg.StartupParams["user"])
	}
	if pg.StartupParams["database"] != "testdb" {
		t.Errorf("Expected database=testdb, got %s", pg.StartupParams["database"])
	}
}

func TestPostgreSQLSimpleQuery(t *testing.T) {
	query := "SELECT * FROM users WHERE id = 1"
	payload := cstr(query)
	data := makeMessage(PGFrontendQuery, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Query: %v", err)
	}

	if pg.MessageType != PGMessageType(PGFrontendQuery) {
		t.Errorf("Expected message type 'Q', got %c", pg.MessageType)
	}
	if !pg.IsRequest {
		t.Error("Expected IsRequest to be true")
	}
	if pg.Query != query {
		t.Errorf("Expected query %q, got %q", query, pg.Query)
	}
}

func TestPostgreSQLParse(t *testing.T) {
	// Parse message: stmt_name + query + num_params + param_oids
	stmt := "stmt1"
	query := "SELECT * FROM users WHERE id = $1"

	payload := []byte{}
	payload = append(payload, cstr(stmt)...)
	payload = append(payload, cstr(query)...)
	// 1 parameter
	payload = append(payload, 0, 1)
	// Parameter type OID (int4 = 23)
	paramOID := make([]byte, 4)
	binary.BigEndian.PutUint32(paramOID, 23)
	payload = append(payload, paramOID...)

	data := makeMessage(PGFrontendParse, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Parse: %v", err)
	}

	if pg.MessageType != PGMessageType(PGFrontendParse) {
		t.Errorf("Expected message type 'P', got %c", pg.MessageType)
	}
	if pg.ParsedStmt != stmt {
		t.Errorf("Expected stmt %q, got %q", stmt, pg.ParsedStmt)
	}
	if pg.ParsedQuery != query {
		t.Errorf("Expected query %q, got %q", query, pg.ParsedQuery)
	}
	if len(pg.ParamTypeOIDs) != 1 || pg.ParamTypeOIDs[0] != 23 {
		t.Errorf("Expected param OIDs [23], got %v", pg.ParamTypeOIDs)
	}
}

func TestPostgreSQLBind(t *testing.T) {
	// Bind message structure
	payload := []byte{}
	payload = append(payload, cstr("portal1")...)   // destination portal
	payload = append(payload, cstr("stmt1")...)     // source statement
	payload = append(payload, 0, 0)                 // 0 format codes
	payload = append(payload, 0, 2)                 // 2 parameter values

	// First param: "42"
	val1 := []byte("42")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(val1)))
	payload = append(payload, lenBuf...)
	payload = append(payload, val1...)

	// Second param: NULL
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFFF) // -1 for NULL
	payload = append(payload, lenBuf...)

	// Result format codes
	payload = append(payload, 0, 1) // 1 result format
	payload = append(payload, 0, 0) // text format

	data := makeMessage(PGFrontendBind, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Bind: %v", err)
	}

	if pg.Portal != "portal1" {
		t.Errorf("Expected portal 'portal1', got %q", pg.Portal)
	}
	if pg.SourceStmt != "stmt1" {
		t.Errorf("Expected source stmt 'stmt1', got %q", pg.SourceStmt)
	}
	if len(pg.ParameterValues) != 2 {
		t.Fatalf("Expected 2 parameter values, got %d", len(pg.ParameterValues))
	}
	if !bytes.Equal(pg.ParameterValues[0], val1) {
		t.Errorf("Expected first param %q, got %q", val1, pg.ParameterValues[0])
	}
	if pg.ParameterValues[1] != nil {
		t.Errorf("Expected second param to be nil (NULL), got %v", pg.ParameterValues[1])
	}
	if len(pg.ResultFormats) != 1 || pg.ResultFormats[0] != 0 {
		t.Errorf("Expected result formats [0], got %v", pg.ResultFormats)
	}
}

func TestPostgreSQLExecute(t *testing.T) {
	payload := []byte{}
	payload = append(payload, cstr("portal1")...)
	// Max rows: 100
	maxRows := make([]byte, 4)
	binary.BigEndian.PutUint32(maxRows, 100)
	payload = append(payload, maxRows...)

	data := makeMessage(PGFrontendExecute, payload)

	pg := &PostgreSQL{}
	// Execute uses 'E' which is ambiguous - set IsRequest to indicate frontend
	pg.IsRequest = true
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Execute: %v", err)
	}

	if pg.ExecutePortal != "portal1" {
		t.Errorf("Expected portal 'portal1', got %q", pg.ExecutePortal)
	}
	if pg.MaxRows != 100 {
		t.Errorf("Expected max rows 100, got %d", pg.MaxRows)
	}
}

func TestPostgreSQLRowDescription(t *testing.T) {
	// RowDescription with 2 columns
	payload := []byte{}

	// Number of fields: 2
	payload = append(payload, 0, 2)

	// Column 1: id (int4)
	payload = append(payload, cstr("id")...)
	col1 := make([]byte, 18)
	binary.BigEndian.PutUint32(col1[0:4], 12345)   // table OID
	binary.BigEndian.PutUint16(col1[4:6], 1)       // column attr
	binary.BigEndian.PutUint32(col1[6:10], 23)     // type OID (int4)
	binary.BigEndian.PutUint16(col1[10:12], 4)     // type size
	binary.BigEndian.PutUint32(col1[12:16], 0xFFFFFFFF) // type modifier (-1)
	binary.BigEndian.PutUint16(col1[16:18], 0)     // format (text)
	payload = append(payload, col1...)

	// Column 2: name (text)
	payload = append(payload, cstr("name")...)
	col2 := make([]byte, 18)
	binary.BigEndian.PutUint32(col2[0:4], 12345)   // table OID
	binary.BigEndian.PutUint16(col2[4:6], 2)       // column attr
	binary.BigEndian.PutUint32(col2[6:10], 25)     // type OID (text)
	binary.BigEndian.PutUint16(col2[10:12], 0xFFFF) // type size (-1, variable)
	binary.BigEndian.PutUint32(col2[12:16], 0xFFFFFFFF) // type modifier (-1)
	binary.BigEndian.PutUint16(col2[16:18], 0)     // format (text)
	payload = append(payload, col2...)

	data := makeMessage(PGBackendRowDescription, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode RowDescription: %v", err)
	}

	if len(pg.Columns) != 2 {
		t.Fatalf("Expected 2 columns, got %d", len(pg.Columns))
	}

	if pg.Columns[0].Name != "id" {
		t.Errorf("Expected column 0 name 'id', got %q", pg.Columns[0].Name)
	}
	if pg.Columns[0].TypeOID != 23 {
		t.Errorf("Expected column 0 type OID 23, got %d", pg.Columns[0].TypeOID)
	}
	if pg.Columns[0].TypeSize != 4 {
		t.Errorf("Expected column 0 type size 4, got %d", pg.Columns[0].TypeSize)
	}

	if pg.Columns[1].Name != "name" {
		t.Errorf("Expected column 1 name 'name', got %q", pg.Columns[1].Name)
	}
	if pg.Columns[1].TypeOID != 25 {
		t.Errorf("Expected column 1 type OID 25, got %d", pg.Columns[1].TypeOID)
	}
	if pg.Columns[1].TypeSize != -1 {
		t.Errorf("Expected column 1 type size -1, got %d", pg.Columns[1].TypeSize)
	}
}

func TestPostgreSQLDataRow(t *testing.T) {
	// DataRow with 2 columns
	payload := []byte{}

	// Number of columns: 2
	payload = append(payload, 0, 2)

	// Column 1: "42"
	val1 := []byte("42")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(val1)))
	payload = append(payload, lenBuf...)
	payload = append(payload, val1...)

	// Column 2: "Alice"
	val2 := []byte("Alice")
	binary.BigEndian.PutUint32(lenBuf, uint32(len(val2)))
	payload = append(payload, lenBuf...)
	payload = append(payload, val2...)

	data := makeMessage(PGBackendDataRow, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode DataRow: %v", err)
	}

	if len(pg.Rows) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(pg.Rows))
	}
	if len(pg.Rows[0]) != 2 {
		t.Fatalf("Expected 2 columns in row, got %d", len(pg.Rows[0]))
	}

	if pg.Rows[0][0].IsNull {
		t.Error("Expected column 0 to not be NULL")
	}
	if !bytes.Equal(pg.Rows[0][0].Data, val1) {
		t.Errorf("Expected column 0 value %q, got %q", val1, pg.Rows[0][0].Data)
	}

	if pg.Rows[0][1].IsNull {
		t.Error("Expected column 1 to not be NULL")
	}
	if !bytes.Equal(pg.Rows[0][1].Data, val2) {
		t.Errorf("Expected column 1 value %q, got %q", val2, pg.Rows[0][1].Data)
	}
}

func TestPostgreSQLDataRowWithNULL(t *testing.T) {
	// DataRow with NULL value
	payload := []byte{}
	payload = append(payload, 0, 2) // 2 columns

	// Column 1: "test"
	val1 := []byte("test")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(val1)))
	payload = append(payload, lenBuf...)
	payload = append(payload, val1...)

	// Column 2: NULL (-1 length)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFFF)
	payload = append(payload, lenBuf...)

	data := makeMessage(PGBackendDataRow, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode DataRow: %v", err)
	}

	if len(pg.Rows) != 1 || len(pg.Rows[0]) != 2 {
		t.Fatalf("Expected 1 row with 2 columns")
	}

	if pg.Rows[0][0].IsNull {
		t.Error("Expected column 0 to not be NULL")
	}
	if !pg.Rows[0][1].IsNull {
		t.Error("Expected column 1 to be NULL")
	}
}

func TestPostgreSQLCommandComplete(t *testing.T) {
	tag := "SELECT 5"
	payload := cstr(tag)
	data := makeMessage(PGBackendCommandComplete, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode CommandComplete: %v", err)
	}

	if pg.CommandTag != tag {
		t.Errorf("Expected command tag %q, got %q", tag, pg.CommandTag)
	}
}

func TestPostgreSQLErrorResponse(t *testing.T) {
	// ErrorResponse with multiple fields
	payload := []byte{}
	payload = append(payload, 'S')
	payload = append(payload, cstr("ERROR")...)
	payload = append(payload, 'V')
	payload = append(payload, cstr("ERROR")...)
	payload = append(payload, 'C')
	payload = append(payload, cstr("42P01")...)
	payload = append(payload, 'M')
	payload = append(payload, cstr("relation \"users\" does not exist")...)
	payload = append(payload, 'D')
	payload = append(payload, cstr("Some detail")...)
	payload = append(payload, 'H')
	payload = append(payload, cstr("Check the table name")...)
	payload = append(payload, 0) // terminal null

	data := makeMessage(PGBackendErrorResponse, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode ErrorResponse: %v", err)
	}

	if pg.ErrorSeverity != "ERROR" {
		t.Errorf("Expected severity 'ERROR', got %q", pg.ErrorSeverity)
	}
	if pg.ErrorCode != "42P01" {
		t.Errorf("Expected code '42P01', got %q", pg.ErrorCode)
	}
	if pg.ErrorMessage != "relation \"users\" does not exist" {
		t.Errorf("Expected message %q, got %q", "relation \"users\" does not exist", pg.ErrorMessage)
	}
	if pg.ErrorFields['D'] != "Some detail" {
		t.Errorf("Expected detail field, got %v", pg.ErrorFields['D'])
	}
	if pg.ErrorFields['H'] != "Check the table name" {
		t.Errorf("Expected hint field, got %v", pg.ErrorFields['H'])
	}
}

func TestPostgreSQLReadyForQuery(t *testing.T) {
	tests := []struct {
		status   byte
		expected PGTransactionStatus
	}{
		{'I', PGTransactionIdle},
		{'T', PGTransactionActive},
		{'E', PGTransactionFailed},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			data := makeMessage(PGBackendReadyForQuery, []byte{tt.status})

			pg := &PostgreSQL{}
			err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
			if err != nil {
				t.Fatalf("Failed to decode ReadyForQuery: %v", err)
			}

			if pg.TransactionStatus != tt.expected {
				t.Errorf("Expected status %v, got %v", tt.expected, pg.TransactionStatus)
			}
		})
	}
}

func TestPostgreSQLParameterStatus(t *testing.T) {
	payload := []byte{}
	payload = append(payload, cstr("server_version")...)
	payload = append(payload, cstr("15.2")...)

	data := makeMessage(PGBackendParameterStatus, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode ParameterStatus: %v", err)
	}

	if pg.ParamName != "server_version" {
		t.Errorf("Expected param name 'server_version', got %q", pg.ParamName)
	}
	if pg.ParamValue != "15.2" {
		t.Errorf("Expected param value '15.2', got %q", pg.ParamValue)
	}
}

func TestPostgreSQLBackendKeyData(t *testing.T) {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], 12345) // process ID
	binary.BigEndian.PutUint32(payload[4:8], 67890) // secret key

	data := makeMessage(PGBackendBackendKeyData, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode BackendKeyData: %v", err)
	}

	if pg.ProcessID != 12345 {
		t.Errorf("Expected process ID 12345, got %d", pg.ProcessID)
	}
	if pg.SecretKey != 67890 {
		t.Errorf("Expected secret key 67890, got %d", pg.SecretKey)
	}
}

func TestPostgreSQLAuth(t *testing.T) {
	// AuthenticationOk (type 0)
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 0)

	data := makeMessage(PGBackendAuth, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Auth: %v", err)
	}

	if pg.AuthType != 0 {
		t.Errorf("Expected auth type 0, got %d", pg.AuthType)
	}
}

func TestPostgreSQLAuthMD5(t *testing.T) {
	// AuthenticationMD5Password (type 5) with 4-byte salt
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], 5)
	copy(payload[4:8], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	data := makeMessage(PGBackendAuth, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Auth MD5: %v", err)
	}

	if pg.AuthType != 5 {
		t.Errorf("Expected auth type 5, got %d", pg.AuthType)
	}
	if !bytes.Equal(pg.AuthData, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("Expected auth data [0xDE, 0xAD, 0xBE, 0xEF], got %v", pg.AuthData)
	}
}

func TestPostgreSQLNotification(t *testing.T) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 9876) // notifying PID
	payload = append(payload, cstr("my_channel")...)
	payload = append(payload, cstr("hello world")...)

	data := makeMessage(PGBackendNotificationResp, payload)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Notification: %v", err)
	}

	if pg.NotifyPID != 9876 {
		t.Errorf("Expected notify PID 9876, got %d", pg.NotifyPID)
	}
	if pg.NotifyChannel != "my_channel" {
		t.Errorf("Expected channel 'my_channel', got %q", pg.NotifyChannel)
	}
	if pg.NotifyPayload != "hello world" {
		t.Errorf("Expected payload 'hello world', got %q", pg.NotifyPayload)
	}
}

func TestPostgreSQLDescribe(t *testing.T) {
	// Describe statement
	payload := []byte{'S'}
	payload = append(payload, cstr("my_stmt")...)

	data := makeMessage(PGFrontendDescribe, payload)

	pg := &PostgreSQL{}
	// Describe uses 'D' which is ambiguous - set IsRequest to indicate frontend
	pg.IsRequest = true
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Describe: %v", err)
	}

	if pg.DescribeType != 'S' {
		t.Errorf("Expected describe type 'S', got %c", pg.DescribeType)
	}
	if pg.DescribeName != "my_stmt" {
		t.Errorf("Expected describe name 'my_stmt', got %q", pg.DescribeName)
	}
}

func TestPostgreSQLClose(t *testing.T) {
	// Close portal
	payload := []byte{'P'}
	payload = append(payload, cstr("my_portal")...)

	data := makeMessage(PGFrontendClose, payload)

	pg := &PostgreSQL{}
	// Close uses 'C' which is ambiguous - set IsRequest to indicate frontend
	pg.IsRequest = true
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode Close: %v", err)
	}

	if pg.CloseType != 'P' {
		t.Errorf("Expected close type 'P', got %c", pg.CloseType)
	}
	if pg.CloseName != "my_portal" {
		t.Errorf("Expected close name 'my_portal', got %q", pg.CloseName)
	}
}

func TestPostgreSQLTooShort(t *testing.T) {
	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes([]byte{}, gopacket.NilDecodeFeedback)
	if err != errPostgreSQLTooShort {
		t.Errorf("Expected errPostgreSQLTooShort, got %v", err)
	}
}

func TestPostgreSQLInvalidLength(t *testing.T) {
	// Message with length < 4 (invalid)
	data := []byte{'Q', 0, 0, 0, 3} // length = 3, which is invalid

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != errPostgreSQLInvalidLength {
		t.Errorf("Expected errPostgreSQLInvalidLength, got %v", err)
	}
}

func TestPostgreSQLTruncated(t *testing.T) {
	// Message claims length 100 but only has 10 bytes
	data := make([]byte, 10)
	data[0] = 'Q'
	binary.BigEndian.PutUint32(data[1:5], 100)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != errPostgreSQLTruncated {
		t.Errorf("Expected errPostgreSQLTruncated, got %v", err)
	}
}

func TestPostgreSQLLayerType(t *testing.T) {
	pg := &PostgreSQL{}
	if pg.LayerType() != LayerTypePostgreSQL {
		t.Error("LayerType() should return LayerTypePostgreSQL")
	}
}

func TestPostgreSQLCanDecode(t *testing.T) {
	pg := &PostgreSQL{}
	if pg.CanDecode() != LayerTypePostgreSQL {
		t.Error("CanDecode() should return LayerTypePostgreSQL")
	}
}

func TestPostgreSQLNextLayerType(t *testing.T) {
	pg := &PostgreSQL{}
	if pg.NextLayerType() != gopacket.LayerTypeZero {
		t.Error("NextLayerType() should return LayerTypeZero")
	}
}

func TestPGTransactionStatusString(t *testing.T) {
	tests := []struct {
		status   PGTransactionStatus
		expected string
	}{
		{PGTransactionIdle, "Idle"},
		{PGTransactionActive, "InTransaction"},
		{PGTransactionFailed, "FailedTransaction"},
		{PGTransactionStatus('X'), "Unknown(X)"},
	}

	for _, tt := range tests {
		if tt.status.String() != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, tt.status.String())
		}
	}
}

func TestPGMessageTypeString(t *testing.T) {
	tests := []struct {
		msgType  PGMessageType
		expected string
	}{
		{PGMessageType(PGFrontendQuery), "Query"},
		// 'D' is ambiguous (Describe frontend, DataRow backend), so String() returns both
		{PGMessageType(PGBackendDataRow), "Describe/DataRow"},
		// 'E' is ambiguous (Execute frontend, ErrorResponse backend), so String() returns both
		{PGMessageType(PGBackendErrorResponse), "Execute/ErrorResponse"},
		{PGMessageType(PGBackendReadyForQuery), "ReadyForQuery"},
	}

	for _, tt := range tests {
		if tt.msgType.String() != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, tt.msgType.String())
		}
	}
}

func TestPostgreSQLCancelRequest(t *testing.T) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:4], 16)              // length
	binary.BigEndian.PutUint32(data[4:8], PGCancelRequestCode) // cancel code
	binary.BigEndian.PutUint32(data[8:12], 12345)          // process ID
	binary.BigEndian.PutUint32(data[12:16], 67890)         // secret key

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode CancelRequest: %v", err)
	}

	if !pg.IsStartupPhase {
		t.Error("Expected IsStartupPhase to be true")
	}
	if !pg.IsRequest {
		t.Error("Expected IsRequest to be true")
	}
	if pg.ProcessID != 12345 {
		t.Errorf("Expected process ID 12345, got %d", pg.ProcessID)
	}
	if pg.SecretKey != 67890 {
		t.Errorf("Expected secret key 67890, got %d", pg.SecretKey)
	}
}

func TestPostgreSQLPayloadAfterMessage(t *testing.T) {
	// Test that payload after message is correctly captured
	query := "SELECT 1"
	payload := cstr(query)
	data := makeMessage(PGFrontendQuery, payload)

	// Append extra data (simulating next message)
	extraData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data = append(data, extraData...)

	pg := &PostgreSQL{}
	err := pg.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if !bytes.Equal(pg.BaseLayer.Payload, extraData) {
		t.Errorf("Expected payload %v, got %v", extraData, pg.BaseLayer.Payload)
	}
}
