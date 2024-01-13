//go:build desktop_access_rdp
// +build desktop_access_rdp

/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package rdpclient

// Some implementation details that don't belong in the public godoc:
// This package wraps a Rust library that ultimately calls IronRDP
// (https://github.com/Devolutions/IronRDP).
//
// The Rust library is statically-compiled and called via CGO.
// The Go code sends and receives the CGO versions of Rust RDP/TDP
// events and passes them to and from the browser.
//
// The flow is roughly this:
//    Go                                Rust
// ==============================================
//  rdpclient.Run -----------------> client_run
//                    *connected*
//                                    run_read_loop
//  handleRDPFastPathPDU <----------- cgo_handle_fastpath_pdu
//  handleRDPFastPathPDU <-----------
//  handleRDPFastPathPDU <-----------
//  			 *fast path (screen) streaming continues...*
//
//              *user input messages*
//                                   run_write_loop
//  ReadMessage(MouseMove) --------> client_write_rdp_pointer
//  ReadMessage(MouseButton) ------> client_write_rdp_pointer
//  ReadMessage(KeyboardButton) ---> client_write_rdp_keyboard
//            *user input continues...*
//
//        *connection closed (client or server side)*
//
//  The wds <--> RDP connection is guaranteed to close when the rust Client is dropped,
//  which happens when client_run returns (typically either due to an error or because
//  client_stop was called).
//
//  The browser <--> wds connection is guaranteed to close when WindowsService.handleConnection
//  returns.

/*
// Flags to include the static Rust library.
#cgo linux,386 LDFLAGS: -L${SRCDIR}/../../../../../target/i686-unknown-linux-gnu/release
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../../../../target/x86_64-unknown-linux-gnu/release
#cgo linux,arm LDFLAGS: -L${SRCDIR}/../../../../../target/arm-unknown-linux-gnueabihf/release
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../../../../target/aarch64-unknown-linux-gnu/release
#cgo linux LDFLAGS: -l:librdp_client.a -lpthread -ldl -lm
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../../../../../target/x86_64-apple-darwin/release
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../../../../../target/aarch64-apple-darwin/release
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security -lrdp_client -lpthread -ldl -lm
#include <librdprs.h>
*/
import "C"

import (
	"context"
	"os"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/lib/srv/desktop/tdp"
	"github.com/gravitational/teleport/lib/utils"
)

func init() {
	// initialize the Rust logger by setting $RUST_LOG based
	// on the logrus log level
	// (unless RUST_LOG is already explicitly set, then we
	// assume the user knows what they want)
	if rl := os.Getenv("RUST_LOG"); rl == "" {
		var rustLogLevel string
		switch l := logrus.GetLevel(); l {
		case logrus.TraceLevel:
			rustLogLevel = "trace"
		case logrus.DebugLevel:
			rustLogLevel = "debug"
		case logrus.InfoLevel:
			rustLogLevel = "info"
		case logrus.WarnLevel:
			rustLogLevel = "warn"
		default:
			rustLogLevel = "error"
		}

		os.Setenv("RUST_LOG", rustLogLevel)
	}

	C.init()
}

// Client is the RDP client.
// Its lifecycle is:
//
// ```
// rdpc := New()         // creates client
// rdpc.Run()   // starts rdp and waits for the duration of the connection
// ```
type Client struct {
	cfg Config

	// Parameters read from the TDP stream.
	clientWidth, clientHeight uint16
	username                  string

	// handle allows the rust code to call back into the client.
	handle cgo.Handle

	// Synchronization point to prevent input messages from being forwarded
	// until the connection is established.
	// Used with sync/atomic, 0 means false, 1 means true.
	readyForInput uint32

	// wg is used to wait for the input/output streaming
	// goroutines to complete
	wg        sync.WaitGroup
	closeOnce sync.Once

	// png2FrameBuffer is used in the handlePNG function
	// to avoid allocation of the buffer on each png as
	// that part of the code is performance-sensitive.
	png2FrameBuffer []byte

	clientActivityMu sync.RWMutex
	clientLastActive time.Time
}

// New creates and connects a new Client based on cfg.
func New(cfg Config) (*Client, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, err
	}
	c := &Client{
		cfg:           cfg,
		readyForInput: 0,
	}

	if err := c.readClientUsername(); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := cfg.AuthorizeFn(c.username); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := c.readClientSize(); err != nil {
		return nil, trace.Wrap(err)
	}
	return c, nil
}

// Run starts the rdp client and blocks until the client disconnects,
// then ensures the cleanup is run.
func (c *Client) Run(ctx context.Context) error {
	// Create a handle to the client to pass to Rust.
	// The handle is used to call back into this Client from Rust.
	// Since the handle is created and deleted here, methods which
	// rely on a valid c.handle can only be called between here and
	// when this function returns.
	c.handle = cgo.NewHandle(c)
	defer c.handle.Delete()

	// Create a channel to signal the startInputStreaming goroutine to stop
	stopCh := make(chan struct{})

	inputStreamingReturnCh := make(chan error, 1)
	// Kick off input streaming goroutine
	go func() {
		inputStreamingReturnCh <- c.startInputStreaming(stopCh)
	}()

	rustRDPReturnCh := make(chan error, 1)
	// Kick off rust RDP loop goroutine
	go func() {
		rustRDPReturnCh <- c.startRustRDP(ctx)
	}()

	select {
	case err := <-rustRDPReturnCh:
		// Ensure the startInputStreaming goroutine returns.
		close(stopCh)
		return trace.Wrap(err)
	case err := <-inputStreamingReturnCh:
		// Ensure the startRustRDP goroutine returns.
		stopErr := c.stopRustRDP()
		return trace.NewAggregate(err, stopErr)
	}
}

func (c *Client) GetClientUsername() string {
	return c.username
}

func (c *Client) readClientUsername() error {
	for {
		msg, err := c.cfg.Conn.ReadMessage()
		if err != nil {
			return trace.Wrap(err)
		}
		u, ok := msg.(tdp.ClientUsername)
		if !ok {
			c.cfg.Log.Debugf("Expected ClientUsername message, got %T", msg)
			continue
		}
		c.cfg.Log.Debugf("Got RDP username %q", u.Username)
		c.username = u.Username
		return nil
	}
}

const (
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cbe1ed0a-d320-4ea5-be5a-f2eb6e032853#Appendix_A_45
	maxRDPScreenWidth  = 8192
	maxRDPScreenHeight = 8192
)

func (c *Client) readClientSize() error {
	for {
		s, err := c.cfg.Conn.ReadClientScreenSpec()
		if err != nil {
			c.cfg.Log.Debug("Error reading client screen spec: %v", err)
			continue
		}

		c.cfg.Log.Debugf("Got RDP screen size %dx%d", s.Width, s.Height)

		if s.Width > maxRDPScreenWidth || s.Height > maxRDPScreenHeight {
			err := trace.BadParameter(
				"screen size of %d x %d is greater than the maximum allowed by RDP (%d x %d)",
				s.Width, s.Height, maxRDPScreenWidth, maxRDPScreenHeight,
			)
			c.cfg.Log.Error(err)
			c.cfg.Conn.WriteMessage(tdp.Notification{Message: err.Error(), Severity: tdp.SeverityError})
		}

		c.clientWidth = uint16(s.Width)
		c.clientHeight = uint16(s.Height)
		return nil
	}
}

func (c *Client) startRustRDP(ctx context.Context) error {
	c.cfg.Log.Info("Rust RDP loop starting")
	defer c.cfg.Log.Info("Rust RDP loop finished")

	userCertDER, userKeyDER, err := c.cfg.GenerateUserCert(ctx, c.username, c.cfg.CertTTL)
	if err != nil {
		return trace.Wrap(err)
	}

	// [addr] need only be valid for the duration of
	// C.client_run. It is copied on the Rust side and
	// thus can be freed here.
	addr := C.CString(c.cfg.Addr)
	defer C.free(unsafe.Pointer(addr))

	cert_der, err := utils.UnsafeSliceData(userCertDER)
	if err != nil {
		return trace.Wrap(err)
	} else if cert_der == nil {
		return trace.BadParameter("user cert was nil")
	}

	key_der, err := utils.UnsafeSliceData(userKeyDER)
	if err != nil {
		return trace.Wrap(err)
	} else if key_der == nil {
		return trace.BadParameter("user key was nil")
	}

	if res := C.client_run(
		C.uintptr_t(c.handle),
		C.CGOConnectParams{
			go_addr: addr,
			// cert length and bytes.
			cert_der_len: C.uint32_t(len(userCertDER)),
			cert_der:     (*C.uint8_t)(cert_der),
			// key length and bytes.
			key_der_len:             C.uint32_t(len(userKeyDER)),
			key_der:                 (*C.uint8_t)(key_der),
			screen_width:            C.uint16_t(c.clientWidth),
			screen_height:           C.uint16_t(c.clientHeight),
			allow_clipboard:         C.bool(c.cfg.AllowClipboard),
			allow_directory_sharing: C.bool(c.cfg.AllowDirectorySharing),
			show_desktop_wallpaper:  C.bool(c.cfg.ShowDesktopWallpaper),
		},
	); res.err_code != C.ErrCodeSuccess {
		if res.message == nil {
			return trace.Errorf("unknown error: %v", res.err_code)
		}
		defer C.free_string(res.message)
		return trace.Errorf("%s", C.GoString(res.message))
	}

	return nil
}

func (c *Client) stopRustRDP() error {
	if errCode := C.client_stop(C.uintptr_t(c.handle)); errCode != C.ErrCodeSuccess {
		return trace.Errorf("client_stop failed: %v", errCode)
	}
	return nil
}

// start_input_streaming kicks off goroutines for input/output streaming and returns right
// away. Use Wait to wait for them to finish.
func (c *Client) startInputStreaming(stopCh chan struct{}) error {
	c.cfg.Log.Info("TDP input streaming starting")
	defer c.cfg.Log.Info("TDP input streaming finished")

	// Remember mouse coordinates to send them with all CGOPointer events.
	var mouseX, mouseY uint32
	for {
		select {
		case <-stopCh:
			return nil
		default:
		}

		msg, err := c.cfg.Conn.ReadMessage()
		if utils.IsOKNetworkError(err) {
			return nil
		} else if tdp.IsNonFatalErr(err) {
			c.cfg.Conn.SendNotification(err.Error(), tdp.SeverityWarning)
			continue
		} else if err != nil {
			c.cfg.Log.Warningf("Failed reading TDP input message: %v", err)
			return err
		}

		if atomic.LoadUint32(&c.readyForInput) == 0 {
			// Input not allowed yet, drop the message.
			c.cfg.Log.Debugf("Dropping TDP input message: %T", msg)
			continue
		}

		c.UpdateClientActivity()

		switch m := msg.(type) {
		case tdp.MouseMove:
			mouseX, mouseY = m.X, m.Y
			if errCode := C.client_write_rdp_pointer(
				C.ulong(c.handle),
				C.CGOMousePointerEvent{
					x:      C.uint16_t(m.X),
					y:      C.uint16_t(m.Y),
					button: C.PointerButtonNone,
					wheel:  C.PointerWheelNone,
				},
			); errCode != C.ErrCodeSuccess {
				return trace.Errorf("MouseMove: client_write_rdp_pointer: %v", errCode)
			}
		case tdp.MouseButton:
			// Map the button to a C enum value.
			var button C.CGOPointerButton
			switch m.Button {
			case tdp.LeftMouseButton:
				button = C.PointerButtonLeft
			case tdp.RightMouseButton:
				button = C.PointerButtonRight
			case tdp.MiddleMouseButton:
				button = C.PointerButtonMiddle
			default:
				button = C.PointerButtonNone
			}
			if errCode := C.client_write_rdp_pointer(
				C.ulong(c.handle),
				C.CGOMousePointerEvent{
					x:      C.uint16_t(mouseX),
					y:      C.uint16_t(mouseY),
					button: uint32(button),
					down:   m.State == tdp.ButtonPressed,
					wheel:  C.PointerWheelNone,
				},
			); errCode != C.ErrCodeSuccess {
				return trace.Errorf("MouseButton: client_write_rdp_pointer: %v", errCode)
			}
		case tdp.MouseWheel:
			var wheel C.CGOPointerWheel
			switch m.Axis {
			case tdp.VerticalWheelAxis:
				wheel = C.PointerWheelVertical
			case tdp.HorizontalWheelAxis:
				wheel = C.PointerWheelHorizontal
				// TDP positive scroll deltas move towards top-left.
				// RDP positive scroll deltas move towards top-right.
				//
				// Fix the scroll direction to match TDP, it's inverted for
				// horizontal scroll in RDP.
				m.Delta = -m.Delta
			default:
				wheel = C.PointerWheelNone
			}
			if errCode := C.client_write_rdp_pointer(
				C.ulong(c.handle),
				C.CGOMousePointerEvent{
					x:           C.uint16_t(mouseX),
					y:           C.uint16_t(mouseY),
					button:      C.PointerButtonNone,
					wheel:       uint32(wheel),
					wheel_delta: C.int16_t(m.Delta),
				},
			); errCode != C.ErrCodeSuccess {
				return trace.Errorf("MouseWheel: client_write_rdp_pointer: %v", errCode)
			}
		case tdp.KeyboardButton:
			if errCode := C.client_write_rdp_keyboard(
				C.ulong(c.handle),
				C.CGOKeyboardEvent{
					code: C.uint16_t(m.KeyCode),
					down: m.State == tdp.ButtonPressed,
				},
			); errCode != C.ErrCodeSuccess {
				return trace.Errorf("KeyboardButton: client_write_rdp_keyboard: %v", errCode)
			}
		case tdp.ClipboardData:
			if !c.cfg.AllowClipboard {
				continue
			}
			if len(m) > 0 {
				if errCode := C.client_update_clipboard(
					C.ulong(c.handle),
					(*C.uint8_t)(unsafe.Pointer(&m[0])),
					C.uint32_t(len(m)),
				); errCode != C.ErrCodeSuccess {
					return trace.Errorf("ClipboardData: client_update_clipboard (len=%v): %v", len(m), errCode)
				}
			} else {
				c.cfg.Log.Warning("Received an empty clipboard message")
			}
		case tdp.SharedDirectoryAnnounce:
			if c.cfg.AllowDirectorySharing {
				driveName := C.CString(m.Name)
				defer C.free(unsafe.Pointer(driveName))
				if errCode := C.client_handle_tdp_sd_announce(C.ulong(c.handle), C.CGOSharedDirectoryAnnounce{
					directory_id: C.uint32_t(m.DirectoryID),
					name:         driveName,
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryAnnounce: failed with %v", errCode)
				}
			}
		case tdp.SharedDirectoryInfoResponse:
			if c.cfg.AllowDirectorySharing {
				path := C.CString(m.Fso.Path)
				defer C.free(unsafe.Pointer(path))
				if errCode := C.client_handle_tdp_sd_info_response(C.ulong(c.handle), C.CGOSharedDirectoryInfoResponse{
					completion_id: C.uint32_t(m.CompletionID),
					err_code:      m.ErrCode,
					fso: C.CGOFileSystemObject{
						last_modified: C.uint64_t(m.Fso.LastModified),
						size:          C.uint64_t(m.Fso.Size),
						file_type:     m.Fso.FileType,
						is_empty:      C.uint8_t(m.Fso.IsEmpty),
						path:          path,
					},
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryInfoResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryCreateResponse:
			if c.cfg.AllowDirectorySharing {
				path := C.CString(m.Fso.Path)
				defer C.free(unsafe.Pointer(path))
				if errCode := C.client_handle_tdp_sd_create_response(C.ulong(c.handle), C.CGOSharedDirectoryCreateResponse{
					completion_id: C.uint32_t(m.CompletionID),
					err_code:      m.ErrCode,
					fso: C.CGOFileSystemObject{
						last_modified: C.uint64_t(m.Fso.LastModified),
						size:          C.uint64_t(m.Fso.Size),
						file_type:     m.Fso.FileType,
						is_empty:      C.uint8_t(m.Fso.IsEmpty),
						path:          path,
					},
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryCreateResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryDeleteResponse:
			if c.cfg.AllowDirectorySharing {
				if errCode := C.client_handle_tdp_sd_delete_response(C.ulong(c.handle), C.CGOSharedDirectoryDeleteResponse{
					completion_id: C.uint32_t(m.CompletionID),
					err_code:      m.ErrCode,
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryDeleteResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryListResponse:
			if c.cfg.AllowDirectorySharing {
				fsoList := make([]C.CGOFileSystemObject, 0, len(m.FsoList))

				for _, fso := range m.FsoList {
					path := C.CString(fso.Path)
					defer C.free(unsafe.Pointer(path))

					fsoList = append(fsoList, C.CGOFileSystemObject{
						last_modified: C.uint64_t(fso.LastModified),
						size:          C.uint64_t(fso.Size),
						file_type:     fso.FileType,
						is_empty:      C.uint8_t(fso.IsEmpty),
						path:          path,
					})
				}

				fsoListLen := len(fsoList)
				var cgoFsoList *C.CGOFileSystemObject

				if fsoListLen > 0 {
					cgoFsoList = (*C.CGOFileSystemObject)(unsafe.Pointer(&fsoList[0]))
				} else {
					cgoFsoList = (*C.CGOFileSystemObject)(unsafe.Pointer(&fsoList))
				}

				if errCode := C.client_handle_tdp_sd_list_response(C.ulong(c.handle), C.CGOSharedDirectoryListResponse{
					completion_id:   C.uint32_t(m.CompletionID),
					err_code:        m.ErrCode,
					fso_list_length: C.uint32_t(fsoListLen),
					fso_list:        cgoFsoList,
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryListResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryReadResponse:
			if c.cfg.AllowDirectorySharing {
				var readData *C.uint8_t
				if m.ReadDataLength > 0 {
					readData = (*C.uint8_t)(unsafe.Pointer(&m.ReadData[0]))
				} else {
					readData = (*C.uint8_t)(unsafe.Pointer(&m.ReadData))
				}

				if errCode := C.client_handle_tdp_sd_read_response(C.ulong(c.handle), C.CGOSharedDirectoryReadResponse{
					completion_id:    C.uint32_t(m.CompletionID),
					err_code:         m.ErrCode,
					read_data_length: C.uint32_t(m.ReadDataLength),
					read_data:        readData,
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryReadResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryWriteResponse:
			if c.cfg.AllowDirectorySharing {
				if errCode := C.client_handle_tdp_sd_write_response(C.ulong(c.handle), C.CGOSharedDirectoryWriteResponse{
					completion_id: C.uint32_t(m.CompletionID),
					err_code:      m.ErrCode,
					bytes_written: C.uint32_t(m.BytesWritten),
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryWriteResponse failed: %v", errCode)
				}
			}
		case tdp.SharedDirectoryMoveResponse:
			if c.cfg.AllowDirectorySharing {
				if errCode := C.client_handle_tdp_sd_move_response(C.ulong(c.handle), C.CGOSharedDirectoryMoveResponse{
					completion_id: C.uint32_t(m.CompletionID),
					err_code:      m.ErrCode,
				}); errCode != C.ErrCodeSuccess {
					return trace.Errorf("SharedDirectoryMoveResponse failed: %v", errCode)
				}
			}
		case tdp.RDPResponsePDU:
			pduLen := uint32(len(m))
			if pduLen == 0 {
				c.cfg.Log.Error("response PDU empty")
			}
			rdpResponsePDU := (*C.uint8_t)(unsafe.SliceData(m))

			if errCode := C.client_handle_tdp_rdp_response_pdu(
				C.ulong(c.handle), rdpResponsePDU, C.uint32_t(pduLen),
			); errCode != C.ErrCodeSuccess {
				return trace.Errorf("RDPResponsePDU failed: %v", errCode)
			}
		default:
			c.cfg.Log.Warningf("Skipping unimplemented TDP message type %T", msg)
		}
	}
}

// asRustBackedSlice creates a Go slice backed by data managed in Rust
// without copying it. The caller must ensure that the data is not freed
// by Rust while the slice is in use.
//
// This can be used in lieu of C.GoBytes (which copies the data) wherever
// performance is of greater concern.
func asRustBackedSlice(data *C.uint8_t, length int) []byte {
	ptr := unsafe.Pointer(data)
	uptr := (*uint8)(ptr)
	return unsafe.Slice(uptr, length)
}

func toClient(handle C.uintptr_t) (value *Client, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = trace.Errorf("panic: %v", r)
		}
	}()
	return cgo.Handle(handle).Value().(*Client), nil
}

//export cgo_handle_fastpath_pdu
func cgo_handle_fastpath_pdu(handle C.uintptr_t, data *C.uint8_t, length C.uint32_t) C.CGOErrCode {
	goData := asRustBackedSlice(data, int(length))
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.handleRDPFastPathPDU(goData)
}

func (c *Client) handleRDPFastPathPDU(data []byte) C.CGOErrCode {
	// Notify the input forwarding goroutine that we're ready for input.
	// Input can only be sent after connection was established, which we infer
	// from the fact that a fast path pdu was sent.
	atomic.StoreUint32(&c.readyForInput, 1)

	if err := c.cfg.Conn.WriteMessage(tdp.RDPFastPathPDU(data)); err != nil {
		c.cfg.Log.Errorf("failed handling RDPFastPathPDU: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_handle_rdp_connection_initialized
func cgo_handle_rdp_connection_initialized(
	handle C.uintptr_t,
	io_channel_id C.uint16_t,
	user_channel_id C.uint16_t,
	screen_width C.uint16_t,
	screen_height C.uint16_t,
) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.handleRDPConnectionInitialized(io_channel_id, user_channel_id, screen_width, screen_height)
}

func (c *Client) handleRDPConnectionInitialized(ioChannelID, userChannelID, screenWidth, screenHeight C.uint16_t) C.CGOErrCode {
	c.cfg.Log.Debugf("Received RDP channel IDs: io_channel_id=%d, user_channel_id=%d", ioChannelID, userChannelID)
	c.cfg.Log.Debugf("RDP server provided resolution of %dx%d", screenWidth, screenHeight)

	if err := c.cfg.Conn.WriteMessage(tdp.ConnectionInitialized{
		IOChannelID:   uint16(ioChannelID),
		UserChannelID: uint16(userChannelID),
		ScreenWidth:   uint16(screenWidth),
		ScreenHeight:  uint16(screenHeight),
	}); err != nil {
		c.cfg.Log.Errorf("failed handling RDPChannelIDs: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_handle_remote_copy
func cgo_handle_remote_copy(handle C.uintptr_t, data *C.uint8_t, length C.uint32_t) C.CGOErrCode {
	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.handleRemoteCopy(goData)
}

// handleRemoteCopy is called from Rust when data is copied
// on the remote desktop
func (c *Client) handleRemoteCopy(data []byte) C.CGOErrCode {
	c.cfg.Log.Debugf("Received %d bytes of clipboard data from Windows desktop", len(data))

	if err := c.cfg.Conn.WriteMessage(tdp.ClipboardData(data)); err != nil {
		c.cfg.Log.Errorf("failed handling remote copy: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_acknowledge
func cgo_tdp_sd_acknowledge(handle C.uintptr_t, ack *C.CGOSharedDirectoryAcknowledge) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryAcknowledge(tdp.SharedDirectoryAcknowledge{
		//nolint:unconvert // Avoid hard dependencies on C types
		ErrCode:     uint32(ack.err_code),
		DirectoryID: uint32(ack.directory_id),
	})
}

// sharedDirectoryAcknowledge is sent by the TDP server to the client
// to acknowledge that a SharedDirectoryAnnounce was received.
func (c *Client) sharedDirectoryAcknowledge(ack tdp.SharedDirectoryAcknowledge) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(ack); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryAcknowledge: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_info_request
func cgo_tdp_sd_info_request(handle C.uintptr_t, req *C.CGOSharedDirectoryInfoRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryInfoRequest(tdp.SharedDirectoryInfoRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		Path:         C.GoString(req.path),
	})
}

// sharedDirectoryInfoRequest is sent from the TDP server to the client
// to request information about a file or directory at a given path.
func (c *Client) sharedDirectoryInfoRequest(req tdp.SharedDirectoryInfoRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryAcknowledge: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_create_request
func cgo_tdp_sd_create_request(handle C.uintptr_t, req *C.CGOSharedDirectoryCreateRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryCreateRequest(tdp.SharedDirectoryCreateRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		//nolint:unconvert // Avoid hard dependencies on C types.
		FileType: uint32(req.file_type),
		Path:     C.GoString(req.path),
	})
}

// sharedDirectoryCreateRequest is sent by the TDP server to
// the client to request the creation of a new file or directory.
func (c *Client) sharedDirectoryCreateRequest(req tdp.SharedDirectoryCreateRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryCreateRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_delete_request
func cgo_tdp_sd_delete_request(handle C.uintptr_t, req *C.CGOSharedDirectoryDeleteRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryDeleteRequest(tdp.SharedDirectoryDeleteRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		Path:         C.GoString(req.path),
	})
}

// sharedDirectoryDeleteRequest is sent by the TDP server to the client
// to request the deletion of a file or directory at path.
func (c *Client) sharedDirectoryDeleteRequest(req tdp.SharedDirectoryDeleteRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryDeleteRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_list_request
func cgo_tdp_sd_list_request(handle C.uintptr_t, req *C.CGOSharedDirectoryListRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryListRequest(tdp.SharedDirectoryListRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		Path:         C.GoString(req.path),
	})
}

// sharedDirectoryListRequest is sent by the TDP server to the client
// to request the contents of a directory.
func (c *Client) sharedDirectoryListRequest(req tdp.SharedDirectoryListRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryListRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_read_request
func cgo_tdp_sd_read_request(handle C.uintptr_t, req *C.CGOSharedDirectoryReadRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryReadRequest(tdp.SharedDirectoryReadRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		Path:         C.GoString(req.path),
		Offset:       uint64(req.offset),
		Length:       uint32(req.length),
	})
}

// SharedDirectoryReadRequest is sent by the TDP server to the client
// to request the contents of a file.
func (c *Client) sharedDirectoryReadRequest(req tdp.SharedDirectoryReadRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryReadRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_write_request
func cgo_tdp_sd_write_request(handle C.uintptr_t, req *C.CGOSharedDirectoryWriteRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryWriteRequest(tdp.SharedDirectoryWriteRequest{
		CompletionID:    uint32(req.completion_id),
		DirectoryID:     uint32(req.directory_id),
		Offset:          uint64(req.offset),
		Path:            C.GoString(req.path),
		WriteDataLength: uint32(req.write_data_length),
		WriteData:       C.GoBytes(unsafe.Pointer(req.write_data), C.int(req.write_data_length)),
	})
}

// SharedDirectoryWriteRequest is sent by the TDP server to the client
// to write to a file.
func (c *Client) sharedDirectoryWriteRequest(req tdp.SharedDirectoryWriteRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryWriteRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess
}

//export cgo_tdp_sd_move_request
func cgo_tdp_sd_move_request(handle C.uintptr_t, req *C.CGOSharedDirectoryMoveRequest) C.CGOErrCode {
	client, err := toClient(handle)
	if err != nil {
		return C.ErrCodeFailure
	}
	return client.sharedDirectoryMoveRequest(tdp.SharedDirectoryMoveRequest{
		CompletionID: uint32(req.completion_id),
		DirectoryID:  uint32(req.directory_id),
		OriginalPath: C.GoString(req.original_path),
		NewPath:      C.GoString(req.new_path),
	})
}

func (c *Client) sharedDirectoryMoveRequest(req tdp.SharedDirectoryMoveRequest) C.CGOErrCode {
	if !c.cfg.AllowDirectorySharing {
		return C.ErrCodeFailure
	}

	if err := c.cfg.Conn.WriteMessage(req); err != nil {
		c.cfg.Log.Errorf("failed to send SharedDirectoryMoveRequest: %v", err)
		return C.ErrCodeFailure
	}
	return C.ErrCodeSuccess

}

// GetClientLastActive returns the time of the last recorded activity.
// For RDP, "activity" is defined as user-input messages
// (mouse move, button press, etc.)
func (c *Client) GetClientLastActive() time.Time {
	c.clientActivityMu.RLock()
	defer c.clientActivityMu.RUnlock()
	return c.clientLastActive
}

// UpdateClientActivity updates the client activity timestamp.
func (c *Client) UpdateClientActivity() {
	c.clientActivityMu.Lock()
	c.clientLastActive = time.Now().UTC()
	c.clientActivityMu.Unlock()
}
