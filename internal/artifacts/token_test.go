package artifacts

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "art_v1_0123456789abcdefABCDEF0123456789abcdef01"
const testExpiry int64 = 1700003600

const testV2Secret = "art_v2_x_syntheticPayload0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-"

var testNow = time.Unix(1700000000, 900000000)

func TestValidateToken(t *testing.T) {
	valid := testSecret + "?expires=" + strconv.FormatInt(testExpiry, 10)
	timestamp := time.Unix(testExpiry, 0).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name, plaintext, expiresAt string
		now                        time.Time
		valid                      bool
	}{
		{"valid", valid, timestamp, testNow, true},
		{"v2", testV2Secret + "?expires=1700003600", timestamp, testNow, true},
		{"v2 fractional expiry", testV2Secret + "?expires=1700003600", "2023-11-14T23:13:20.755Z", testNow, true},
		{"v2 empty payload", "art_v2_x_?expires=1700003600", timestamp, testNow, false},
		{"v2 unknown variant", "art_v2_y_payload?expires=1700003600", timestamp, testNow, false},
		{"unknown version", "art_v3_x_payload?expires=1700003600", timestamp, testNow, false},
		{"v2 oversized", "art_v2_x_" + strings.Repeat("a", 4096) + "?expires=1700003600", timestamp, testNow, false},
		{"v2 whitespace", testV2Secret + " ?expires=1700003600", timestamp, testNow, false},
		{"v2 control", testV2Secret + "\n?expires=1700003600", timestamp, testNow, false},
		{"v2 unicode", testV2Secret + "é?expires=1700003600", timestamp, testNow, false},
		{"v2 query delimiter", testV2Secret + "&other=value?expires=1700003600", timestamp, testNow, false},
		{"v2 expired", testV2Secret + "?expires=1700003600", timestamp, time.Unix(testExpiry, 0), false},
		{"v2 expiry mismatch", testV2Secret + "?expires=1700003601", timestamp, testNow, false},
		{"v2 missing suffix", testV2Secret, timestamp, testNow, false},
		{"fractional seconds", valid, time.Unix(testExpiry, 999999999).UTC().Format(time.RFC3339Nano), testNow, true},
		{"offset", valid, time.Unix(testExpiry, 0).In(time.FixedZone("offset", 3600)).Format(time.RFC3339), testNow, true},
		{"leading zero suffix", testSecret + "?expires=0" + strconv.FormatInt(testExpiry, 10), timestamp, testNow, true},
		{"one second before expiry", valid, timestamp, time.Unix(testExpiry-1, 999999999), true},
		{"at expiry", valid, timestamp, time.Unix(testExpiry, 0), false},
		{"past expiry", valid, timestamp, time.Unix(testExpiry+1, 0), false},
		{"empty plaintext", "", timestamp, testNow, false},
		{"missing suffix", testSecret, timestamp, testNow, false},
		{"empty suffix", testSecret + "?expires=", timestamp, testNow, false},
		{"repeated suffix", valid + "?expires=1700003600", timestamp, testNow, false},
		{"different suffix", testSecret + "?expiry=1700003600", timestamp, testNow, false},
		{"negative suffix", testSecret + "?expires=-1700003600", timestamp, testNow, false},
		{"positive sign", testSecret + "?expires=+1700003600", timestamp, testNow, false},
		{"space suffix", valid + " ", timestamp, testNow, false},
		{"newline suffix", valid + "\n", timestamp, testNow, false},
		{"decimal suffix", valid + ".0", timestamp, testNow, false},
		{"extra query", valid + "&scope=write", timestamp, testNow, false},
		{"unicode digits", testSecret + "?expires=１７００００３６００", timestamp, testNow, false},
		{"suffix overflow", testSecret + "?expires=9223372036854775808", timestamp, testNow, false},
		{"huge suffix", testSecret + "?expires=" + strings.Repeat("9", 100), timestamp, testNow, false},
		{"zero suffix", testSecret + "?expires=0", "1970-01-01T00:00:00Z", time.Unix(-1, 0), false},
		{"wrong version", strings.Replace(valid, "art_v1_", "art_v2_", 1), timestamp, testNow, false},
		{"short hex", "art_v1_" + strings.Repeat("a", 39) + "?expires=1700003600", timestamp, testNow, false},
		{"long hex", "art_v1_" + strings.Repeat("a", 41) + "?expires=1700003600", timestamp, testNow, false},
		{"non hex", "art_v1_" + strings.Repeat("g", 40) + "?expires=1700003600", timestamp, testNow, false},
		{"control secret", "art_v1_" + strings.Repeat("a", 39) + "\x00?expires=1700003600", timestamp, testNow, false},
		{"empty expires_at", valid, "", testNow, false},
		{"bad expires_at", valid, "seeded-repository-secret", testNow, false},
		{"numeric expires_at", valid, "1700003600", testNow, false},
		{"date only", valid, "2023-11-14", testNow, false},
		{"no timezone", valid, strings.TrimSuffix(timestamp, "Z"), testNow, false},
		{"invalid date", valid, "2023-02-30T23:13:20Z", testNow, false},
		{"one digit hour", valid, "2023-11-14T1:13:20Z", testNow, false},
		{"comma fraction", valid, strings.TrimSuffix(timestamp, "Z") + ",1Z", testNow, false},
		{"invalid timezone hour", valid, strings.TrimSuffix(timestamp, "Z") + "+24:00", testNow, false},
		{"invalid timezone minute", valid, strings.TrimSuffix(timestamp, "Z") + "+00:60", testNow, false},
		{"timestamp mismatch", valid, time.Unix(testExpiry+1, 0).UTC().Format(time.RFC3339), testNow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateToken(tc.plaintext, tc.expiresAt, tc.now)
			if tc.valid {
				if err != nil || got != (Token{strings.Split(tc.plaintext, "?expires=")[0], testExpiry}) {
					t.Fatal("valid token not preserved with reconciled expiry")
				}
			} else if err != ErrTokenResponse || got != (Token{}) {
				t.Fatal("invalid response accepted or partially returned")
			}
		})
	}
}

func FuzzValidateToken(f *testing.F) {
	f.Add(testSecret+"?expires=1700003600", time.Unix(testExpiry, 0).UTC().Format(time.RFC3339))
	f.Add(testV2Secret+"?expires=1700003600", time.Unix(testExpiry, 0).UTC().Format(time.RFC3339))
	f.Add("", "")
	f.Fuzz(func(t *testing.T, plaintext, expiresAt string) {
		got, err := validateToken(plaintext, expiresAt, testNow)
		if err != nil {
			if got != (Token{}) || err != ErrTokenResponse {
				t.Fatal("unsafe failure")
			}
			return
		}
		if got.ExpiryUnix <= testNow.Unix() || got.Secret+"?expires="+strings.Split(plaintext, "?expires=")[1] != plaintext || !validTokenSecret(got.Secret) {
			t.Fatal("invalid successful token")
		}
	})
}
