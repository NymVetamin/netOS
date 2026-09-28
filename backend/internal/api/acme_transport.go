package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// x/crypto/acme loses the order URI when finalize omits Location. RFC8555
// permits polling the already-known order; preserve that exact URI rather
// than deriving one from the CA's implementation-specific URL layout.
type acmeOrderTransport struct {
	base   http.RoundTripper
	mu     sync.Mutex
	orders map[string]acmeOrderLocation
}
type acmeOrderLocation struct {
	uri     string
	created time.Time
}
type replayResponseBody struct {
	io.Reader
	io.Closer
}

func (t *acmeOrderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if req.Method != http.MethodPost || res.StatusCode < 200 || res.StatusCode >= 300 {
		return res, nil
	}
	t.mu.Lock()
	if order, ok := t.orders[req.URL.String()]; ok {
		if time.Since(order.created) < time.Hour && res.Header.Get("Location") == "" {
			res.Header = res.Header.Clone()
			res.Header.Set("Location", order.uri)
		}
		delete(t.orders, req.URL.String())
	}
	t.mu.Unlock()
	// Only a newly-created order can teach us its finalize -> order mapping.
	if res.StatusCode != http.StatusCreated || res.Header.Get("Location") == "" {
		return res, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		res.Body.Close()
		return nil, err
	}
	res.Body = replayResponseBody{io.MultiReader(bytes.NewReader(body), res.Body), res.Body}
	var order struct {
		Finalize string `json:"finalize"`
		Status   string `json:"status"`
	}
	if json.Unmarshal(body, &order) != nil || order.Finalize == "" || order.Status == "" {
		return res, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.orders == nil {
		t.orders = map[string]acmeOrderLocation{}
	}
	for key, value := range t.orders {
		if time.Since(value.created) >= time.Hour {
			delete(t.orders, key)
		}
	}
	if len(t.orders) < 128 {
		t.orders[order.Finalize] = acmeOrderLocation{res.Header.Get("Location"), time.Now()}
	}
	return res, nil
}
