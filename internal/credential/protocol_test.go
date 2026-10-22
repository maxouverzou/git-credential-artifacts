package credential

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"testing/iotest"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Request
	}{
		{"empty EOF", "", Request{}},
		{"blank line", "\nignored malformed data", Request{}},
		{"complete", "protocol=https\nhost=example.com\npath=git/default/demo.git\nusername=user\n\n", Request{"https", "example.com", "git/default/demo.git", "user"}},
		{"EOF without LF", "host=example.com", Request{Host: "example.com"}},
		{"EOF after LF", "host=example.com\n", Request{Host: "example.com"}},
		{"empty values", "protocol=\nhost=\npath=\nusername=\n\n", Request{}},
		{"equals in value", "username=user=with=equals\n\n", Request{Username: "user=with=equals"}},
		{"unknown fields and arrays", "password=synthetic-secret\nurl=https://ignored.invalid\nfuture=x\nfuture=y\ncapability[]=a\ncapability[]=b\n\n", Request{}},
		{"stop at blank line", "host=first\n\nhost=second\n", Request{Host: "first"}},
		{"byte values", "username=\xff\n\n", Request{Username: "\xff"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, wrap := range []func(io.Reader) io.Reader{
				func(r io.Reader) io.Reader { return r },
				iotest.OneByteReader,
				iotest.HalfReader,
				iotest.DataErrReader,
			} {
				got, err := Parse(wrap(strings.NewReader(test.input)))
				if err != nil || got != test.want {
					t.Fatalf("Parse returned %v, %v; want %v", got, err, test.want)
				}
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	inputs := []string{
		"malformed\n", "=empty-key\n", "host\n",
		"host=one\nhost=one\n", "protocol=\nprotocol=https\n",
		"path=one\npath=two\n", "username=user\nusername=attacker\n",
		"host=example.com\nusername=user\nquit\n", // embedded malformed line
		"host=example.com\r\n", "unknown=\x00\n", "bad\x00key=value\n",
		"unknown=\r\n", "username=user\tname\n", "username=user\x7f\n",
		"username=user\u0085\n", "bad\tkey=value\n",
	}
	for _, input := range inputs {
		got, err := Parse(strings.NewReader(input))
		if !errors.Is(err, ErrInvalidInput) || got != (Request{}) {
			t.Fatalf("invalid input must fail without partial request: %q", input)
		}
	}
}

func TestParseSizeBounds(t *testing.T) {
	maxLine := "future=" + strings.Repeat("a", MaxLineBytes-len("future=")-1) + "\n"
	for _, input := range []string{maxLine, maxLine + "\n"} {
		if _, err := Parse(strings.NewReader(input)); err != nil {
			t.Fatal("maximum-size line should be accepted", err)
		}
	}
	for _, input := range []string{maxLine + "a=\n", strings.TrimSuffix(maxLine, "\n") + "a\n"} {
		// The first record exceeds the total bound; the second exceeds the line bound.
		if got, err := Parse(strings.NewReader(input)); !errors.Is(err, ErrInputTooLarge) || got != (Request{}) {
			t.Fatal("oversized input must fail without partial request")
		}
	}
	exact := strings.Repeat("a=b\n", MaxInputBytes/4)
	if _, err := Parse(strings.NewReader(exact)); err != nil {
		t.Fatal("exact total bound should be accepted", err)
	}
	if _, err := Parse(strings.NewReader(exact + "\n")); !errors.Is(err, ErrInputTooLarge) {
		t.Fatal("terminating blank line must count toward total bound")
	}
	reader := &countingReader{Reader: strings.NewReader(strings.Repeat("a", MaxInputBytes*3))}
	if _, err := Parse(reader); !errors.Is(err, ErrInputTooLarge) {
		t.Fatal("long unterminated line must fail")
	}
	if reader.count > MaxInputBytes+1 {
		t.Fatal("parser read beyond bounded lookahead")
	}
}

type countingReader struct {
	io.Reader
	count int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.count += n
	return n, err
}

func TestParseReadErrors(t *testing.T) {
	for _, prefix := range []string{"", "host=partial", "host=partial\n"} {
		reader := io.MultiReader(strings.NewReader(prefix), iotest.ErrReader(errors.New("synthetic-secret-reader-error")))
		got, err := Parse(reader)
		if !errors.Is(err, ErrReadInput) || got != (Request{}) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("read failure must be sanitized and discard partial input")
		}
	}
}

func TestWriteResponse(t *testing.T) {
	var output bytes.Buffer
	response := Response{"user=equals", "synthetic=token", 1760000000}
	if err := WriteResponse(&output, response); err != nil {
		t.Fatal(err)
	}
	want := "username=user=equals\npassword=synthetic=token\npassword_expiry_utc=1760000000\n\n"
	if output.String() != want {
		t.Fatalf("unexpected protocol output: %q", output.String())
	}
	output.Reset()
	if err := WriteQuit(&output); err != nil || output.String() != "quit=true\n\n" {
		t.Fatal("quit must be a standalone blank-line-terminated record")
	}
	response.ExpiryUnix = math.MaxInt64
	output.Reset()
	if err := WriteResponse(&output, response); err != nil || !strings.Contains(output.String(), "password_expiry_utc=9223372036854775807\n\n") {
		t.Fatal("expiry must retain its full int64 Unix-second value")
	}
}

func TestWriteInvalidResponse(t *testing.T) {
	valid := Response{"user", "synthetic-token", 1760000000}
	inputs := []Response{
		{"", valid.Password, valid.ExpiryUnix},
		{valid.Username, "", valid.ExpiryUnix},
		{valid.Username, valid.Password, 0},
		{valid.Username, valid.Password, -1},
		{strings.Repeat("a", MaxLineBytes), valid.Password, valid.ExpiryUnix},
		{valid.Username, strings.Repeat("a", MaxLineBytes), valid.ExpiryUnix},
		{strings.Repeat("a", MaxInputBytes/2), strings.Repeat("b", MaxInputBytes/2), valid.ExpiryUnix},
	}
	for _, control := range []string{"\nquit=true", "\r", "\x00", "\t", "\x7f", "\u0085"} {
		inputs = append(inputs,
			Response{"user" + control, valid.Password, valid.ExpiryUnix},
			Response{valid.Username, "synthetic-token" + control, valid.ExpiryUnix})
	}
	for _, response := range inputs {
		var output bytes.Buffer
		if err := WriteResponse(&output, response); !errors.Is(err, ErrInvalidResponse) || output.Len() != 0 {
			t.Fatal("invalid response must not write partial credentials")
		}
	}
}

type brokenWriter struct {
	n     int
	err   error
	calls int
}

func (w *brokenWriter) Write(p []byte) (int, error) {
	w.calls++
	return min(w.n, len(p)), w.err
}

func TestWriteErrors(t *testing.T) {
	for _, write := range []func(io.Writer) error{
		func(w io.Writer) error { return WriteResponse(w, Response{"user", "synthetic-token", 1}) },
		WriteQuit,
	} {
		for _, test := range []struct {
			n         int
			err, want error
		}{
			{0, io.ErrClosedPipe, io.ErrClosedPipe},
			{5, io.ErrClosedPipe, io.ErrClosedPipe},
			{5, nil, io.ErrShortWrite},
		} {
			writer := &brokenWriter{n: test.n, err: test.err}
			if err := write(writer); !errors.Is(err, test.want) || writer.calls != 1 {
				t.Fatal("write failure must propagate without retry")
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"", "\n", "protocol=https\nhost=example.com\npath=git/default/demo.git\n\n",
		"username=a=b", "host=one\nhost=two\n", "unknown=\x00",
		"username=user\r\n", "host=one\n\nmalformed",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		request, err := Parse(strings.NewReader(input))
		if err != nil {
			if request != (Request{}) {
				t.Fatal("parse failure retained partial input")
			}
			return
		}
		for _, value := range []string{request.Protocol, request.Host, request.Path, request.Username} {
			if hasControl(value) {
				t.Fatal("accepted control in parsed value")
			}
		}
	})
}

func FuzzWriteResponse(f *testing.F) {
	f.Add("user", "synthetic-token", int64(1760000000))
	f.Add("user\nquit=true", "token", int64(1))
	f.Fuzz(func(t *testing.T, username, password string, expiry int64) {
		var output bytes.Buffer
		err := WriteResponse(&output, Response{username, password, expiry})
		if err != nil {
			if output.Len() != 0 {
				t.Fatal("invalid response produced output")
			}
			return
		}
		lines := strings.Split(output.String(), "\n")
		if len(lines) != 5 || lines[0] != "username="+username || lines[1] != "password="+password ||
			!strings.HasPrefix(lines[2], "password_expiry_utc=") || lines[3] != "" || lines[4] != "" {
			t.Fatal("response injected an additional protocol field")
		}
	})
}
