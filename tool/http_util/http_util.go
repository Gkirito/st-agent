package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"time"
)

type ErrHttp struct {
	StatusCode int
	Body       []byte
}

func (e ErrHttp) Error() string {
	return fmt.Sprintf("Code: %d Body: %s", e.StatusCode, string(e.Body))
}

func JsonReq[T any](ctx context.Context, method, URL string, params url.Values, headers http.Header, body any) (resp T, err error) {
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set("Content-Type", "application/json")
	buf := bytes.NewBuffer([]byte{})
	err = json.NewEncoder(buf).Encode(body)
	if err != nil {
		return
	}
	respBody, err := Request(ctx, method, URL, params, headers, buf)
	if err != nil {
		return
	}

	return resp, json.Unmarshal(respBody, &resp)
}

func Request(ctx context.Context, method, URL string, params url.Values, headers http.Header, body io.Reader) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if len(params) > 0 {
		baseURL, err := url.Parse(URL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}
		q := baseURL.Query()
		maps.Insert(q, maps.All(params))
		baseURL.RawQuery = q.Encode()
		URL = baseURL.String()
	}

	req, err := http.NewRequestWithContext(ctx, method, URL, body)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		maps.Insert(req.Header, maps.All(headers))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, ErrHttp{StatusCode: resp.StatusCode, Body: respBody}
	}
	return respBody, nil
}
