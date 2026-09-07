package tsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	tcrypto "github.com/isri-pqc/go-asice/tsa/crypto"
)

// maxResponseSize is the maximum accepted timestamp-reply body size
// (10 KiB; the limit of the Estonian e-voting collector's TSP client).
const maxResponseSize = 10240

// OidSHA256 is the SHA-256 digest algorithm OID (RFC 3161). The client
// hashes the queried data with SHA-256, as the collector's TSP client does.
var OidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// DefaultTimeout bounds a single TSA exchange (one request and
// response attempt, including the dial). It exists so a stalled or
// hostile TSA that accepts the TCP connection but never responds
// cannot hang the client indefinitely; such a TSA fails the exchange
// as a timeout and is then retried like any other transport error.
const DefaultTimeout = 30 * time.Second

// defaultHTTPClient is the package default HTTP client used when
// Client.HTTPClient is nil; it applies DefaultTimeout so a stalled TSA
// fails instead of hanging. It is a variable so tests can substitute
// a short-timeout client.
var defaultHTTPClient = &http.Client{Timeout: DefaultTimeout}

// Client requests time-stamps from a configured TSA (RFC 3161).
type Client struct {
	// URL is the TSA endpoint (POST, application/timestamp-query).
	URL string
	// Policy is the required time-stamping policy OID. A TimeStampReq
	// carries no policy field (the TSA selects its own), so when this
	// is set, Create rejects tokens whose TSTInfo policy differs.
	// When empty (default), any policy is accepted: the
	// collector's TSP client never compares the policy value.
	Policy asn1.ObjectIdentifier
	// MaxAge and MaxSkew are the genTime freshness bounds applied to
	// fresh tokens; the defaults mirror the collector's TSP client
	// (1 minute, 2 seconds).
	MaxAge  time.Duration
	MaxSkew time.Duration
	// TSTSigners is the configured TSA-signing certificate pool used
	// to identify the signing certificate. The Estonian e-voting
	// collector's TSP client requires this pool and cannot verify the
	// token signature without it. Required.
	TSTSigners []*x509.Certificate
	// DigestModule computes the message imprint digest of the queried
	// data (SHA-256, mirroring the collector's TSP client). Required.
	DigestModule tcrypto.DigestModule
	// SignatureVerifierModule verifies the token's CMS signature
	// (mirroring the collector's client, which verifies the token
	// signature against its configured TSA signers). Required.
	SignatureVerifierModule tcrypto.SignatureVerifierModule
	// Retry is the number of additional attempts after a 5xx response
	// or transport error (mirroring the collector's retry setting).
	Retry uint
	// HTTPClient is the HTTP client used for requests (default
	// defaultHTTPClient, bounded by DefaultTimeout).
	HTTPClient *http.Client
}

// NewClient returns a Client with the collector-equivalent defaults
// (MaxAge 1 minute, MaxSkew 2 seconds).
func NewClient(url string) *Client {
	return &Client{URL: url, MaxAge: DefaultMaxAge, MaxSkew: DefaultMaxSkew}
}

// Create requests a time-stamp over data and validates the response.
// It returns the token bytes (ready for xades:EncapsulatedTimeStamp)
// and the token generation time. When nonce is nil, a random 20-byte
// nonce is generated (as the collector's TSP client does); the TSA
// must echo it in the TST, and Create verifies the echo.
//
// Create does NOT verify the signing certificate chain — it performs
// the same checks the Estonian e-voting collector's TSP client Create
// does (TSTInfo, imprint, nonce, signed data, signature over them,
// freshness); run the result
// through Validator.Check for full validation against roots.
func (c *Client) Create(ctx context.Context, data []byte, nonce *big.Int) ([]byte, time.Time, error) {
	if c.URL == "" {
		return nil, time.Time{}, errors.New("tsa: client has no URL configured")
	}
	if len(c.TSTSigners) == 0 {
		return nil, time.Time{}, errors.New("tsa: client has no TST signers configured")
	}
	if c.DigestModule == nil || c.SignatureVerifierModule == nil {
		return nil, time.Time{}, errors.New("tsa: client requires the crypto modules (DigestModule, SignatureVerifierModule)")
	}
	if len(data) == 0 {
		return nil, time.Time{}, errors.New("tsa: no data to time-stamp")
	}
	if nonce == nil {
		buf := make([]byte, 20)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, time.Time{}, fmt.Errorf("tsa: generate nonce: %w", err)
		}
		nonce = new(big.Int).SetBytes(buf)
	}
	sum, err := c.DigestModule.GetDigestFunc(OidSHA256)(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tsa: digest the queried data: %w", err)
	}
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OidSHA256, Parameters: asn1.RawValue{FullBytes: asn1.NullBytes}},
			HashedMessage: sum,
		},
		Nonce:   nonce,
		CertReq: true,
	}
	reqDER, err := req.Encode()
	if err != nil {
		return nil, time.Time{}, err
	}

	respDER, err := c.submit(ctx, reqDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	resp, err := ParseTimeStampResp(respDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	if resp.Status.Status != 0 {
		return nil, time.Time{}, fmt.Errorf("tsa: TSA rejected the request: pkiStatus %d %v",
			resp.Status.Status, resp.Status.StatusString)
	}
	if resp.TimeStampToken == nil {
		return nil, time.Time{}, errors.New("tsa: pkiStatus 0 but no TimeStampToken in response")
	}

	// Structural + freshness validation (the checks the collector's
	// TSP client Create applies); chain validation is Validator.Check's
	// job.
	v := &Validator{
		MaxAge:                  c.MaxAge,
		MaxSkew:                 c.MaxSkew,
		TSTSigners:              c.TSTSigners,
		DigestModule:            c.DigestModule,
		SignatureVerifierModule: c.SignatureVerifierModule,
	}
	gen, err := v.checkTokenBody(resp.TimeStampToken.DER, data, nonce, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(c.Policy) > 0 {
		parsed, err := Parse(resp.TimeStampToken.DER)
		if err != nil {
			return nil, time.Time{}, err
		}
		if policy := parsed.Content.EncapContentInfo.TSTInfo.Policy; !policy.Equal(c.Policy) {
			return nil, time.Time{}, fmt.Errorf("tsa: token policy %s, want %s", policy, c.Policy)
		}
	}
	return resp.TimeStampToken.DER, gen, nil
}

// checkTokenBody runs the non-trust token checks (TSTInfo, imprint,
// nonce, signed data, signature) plus the genTime freshness check
// against now.
func (v *Validator) checkTokenBody(token, data []byte, nonce *big.Int, now time.Time) (time.Time, error) {
	maxAge := v.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}

	tsToken, err := Parse(token)
	if err != nil {
		return time.Time{}, err
	}
	info := tsToken.Content.EncapContentInfo.TSTInfo
	if info.Version != 1 {
		return time.Time{}, fmt.Errorf("tsa: TSTInfo version %d, want 1", info.Version)
	}
	digest, err := v.DigestModule.GetDigestFunc(info.MessageImprint.HashAlgorithm.Algorithm)(data)
	if err != nil {
		return time.Time{}, fmt.Errorf("tsa: message imprint: %w", err)
	}
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest) {
		return time.Time{}, errors.New("tsa: message imprint does not match the digest of the queried data")
	}
	if nonce != nil {
		if info.Nonce == nil {
			return time.Time{}, errors.New("tsa: nonce was requested but is missing from the TST")
		}
		if info.Nonce.Cmp(nonce) != 0 {
			return time.Time{}, fmt.Errorf("tsa: nonce mismatch: TST has %s", info.Nonce)
		}
	}
	if err := checkGenTime(now, info.GenTime, info.Accuracy, maxAge, maxSkew); err != nil {
		return time.Time{}, err
	}
	if err := v.checkSignedData(tsToken, info.GenTime); err != nil {
		return time.Time{}, err
	}
	return info.GenTime, nil
}

// submit POSTs the request and returns the raw timestamp-reply body.
// 5xx responses and transport errors are retried (c.Retry additional
// attempts, 1s apart), mirroring the collector's TSP client retry behavior.
func (c *Client) submit(ctx context.Context, reqDER []byte) ([]byte, error) {
	hc := c.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient
	}
	for attempt := uint(0); ; attempt++ {
		body, err := c.do(ctx, hc, reqDER)
		if err == nil {
			return body, nil
		}
		if attempt < c.Retry && isRetryable(err) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		return nil, err
	}
}

// tsErr marks transport-level and 5xx response errors so submit can
// decide whether to retry (mirroring the collector's retry decision).
type tsErr struct {
	retryable bool
	err       error
}

func (e *tsErr) Error() string { return e.err.Error() }
func (e *tsErr) Unwrap() error { return e.err }

func isRetryable(err error) bool {
	var t *tsErr
	return errors.As(err, &t) && t.retryable
}

func (c *Client) do(ctx context.Context, hc *http.Client, reqDER []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("tsa: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeQuery)

	httpResp, err := hc.Do(httpReq)
	if err != nil {
		return nil, &tsErr{retryable: true, err: fmt.Errorf("tsa: TSA request failed: %w", err)}
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		retryable := httpResp.StatusCode >= 500 && httpResp.StatusCode < 600
		return nil, &tsErr{retryable: retryable, err: fmt.Errorf("tsa: TSA responded with status %d", httpResp.StatusCode)}
	}
	if ct := httpResp.Header.Get("Content-Type"); ct != ContentTypeReply {
		return nil, fmt.Errorf("tsa: unexpected response content type %q, want %q", ct, ContentTypeReply)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseSize+1))
	if err != nil {
		return nil, &tsErr{retryable: true, err: fmt.Errorf("tsa: read response body: %w", err)}
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("tsa: response body exceeds %d bytes", maxResponseSize)
	}
	return body, nil
}
