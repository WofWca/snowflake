package snowflake_server

import (
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/consenthandshake"
)

func TestClientAddr(t *testing.T) {
	Convey("Testing clientAddr", t, func() {
		// good tests
		for _, test := range []struct {
			input    string
			expected net.IP
		}{
			{"1.2.3.4", net.ParseIP("1.2.3.4")},
			{"1:2::3:4", net.ParseIP("1:2::3:4")},
		} {
			useraddr := clientAddr(test.input).String()
			host, port, err := net.SplitHostPort(useraddr)
			if err != nil {
				t.Errorf("clientAddr(%q) → SplitHostPort error %v", test.input, err)
				continue
			}
			if !test.expected.Equal(net.ParseIP(host)) {
				t.Errorf("clientAddr(%q) → host %q, not %v", test.input, host, test.expected)
			}
			portNo, err := strconv.Atoi(port)
			if err != nil {
				t.Errorf("clientAddr(%q) → port %q", test.input, port)
				continue
			}
			if portNo == 0 {
				t.Errorf("clientAddr(%q) → port %d", test.input, portNo)
			}
		}

		// bad tests
		for _, input := range []string{
			"",
			"abc",
			"1.2.3.4.5",
			"[12::34]",
			"0.0.0.0",
			"[::]",
		} {
			useraddr := clientAddr(input).String()
			if useraddr != "" {
				t.Errorf("clientAddr(%q) → %q, not %q", input, useraddr, "")
			}
		}
	})
}

func TestConsentHandshake(t *testing.T) {
	Convey("getConsentChallengeResponse", t, func() {
		for _, test := range []struct {
			input    string
			expected string
		}{
			{"DEADBEEF", "8dc3d198"},
			{"1337ABCD", "4059c4ba"},
			{"00000000", hex.EncodeToString([]byte("Snow"))},
			{
				"0000000000000000000000000000000000000000000000000000000000000000",
				hex.EncodeToString(consenthandshake.ChallengeKey[:]),
			},
			// Invalid chars
			{"XXXX", ""},
			// Even length
			{"111", ""},
			// Too long (odd length)
			{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ""},
			{"53", "00"},
			{"", ""},
		} {
			responseText, err := getConsentChallengeResponse(test.input)
			if responseText != test.expected {
				t.Errorf("Expected: %v. Got %v, %v", test.expected, responseText, err)
			}
		}
	})
	Convey("responds to consent handshake requests", t, func() {
		w := httptest.NewRecorder()
		handler := httpHandler{}

		Convey("with consent response to a consent request", func() {
			r, err := http.NewRequest(
				"HEAD",
				"https://snowflake-server.com/any_path",
				nil,
			)
			So(err, ShouldBeNil)
			r.Header.Add(consenthandshake.RequestHeader, "DeADbEeF")
			handler.ServeHTTP(w, r)
			So(w.Code, ShouldEqual, http.StatusOK)
			So(w.Header().Get(consenthandshake.ResponseHeader), ShouldEqual, "8dc3d198")
		})

		Convey("with an error value in the header on invalid challenge string", func() {
			r, err := http.NewRequest(
				"HEAD",
				"https://snowflake-server.com/",
				nil,
			)
			So(err, ShouldBeNil)
			r.Header.Add(consenthandshake.RequestHeader, "AAA")
			handler.ServeHTTP(w, r)
			So(w.Code, ShouldEqual, http.StatusOK)
			So(
				w.Header().Get(consenthandshake.ResponseHeader),
				ShouldStartWith,
				"failed to hex decode the challenge string:",
			)
		})

		Convey("with WS connection to regular requests", func() {
			r, err := http.NewRequest(
				"GET",
				"wss://snowflake-server.com/any_path",
				nil,
			)
			So(err, ShouldBeNil)

			// https://github.com/gorilla/websocket/blob/5e002381133d322c5f1305d171f3bdd07decf229/server.go#L124-L284
			r.Header.Add("Connection", "upgrade")
			r.Header.Add("Upgrade", "websocket")
			r.Header.Add("Sec-Websocket-Version", "13")

			handler.ServeHTTP(w, r)
			// It's not easy to mock a WebSocket connection by hand,
			// so let's just do this.
			So(w.Code, ShouldEqual, http.StatusBadRequest)
		})
	})
}
