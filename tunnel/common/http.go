package common

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

func GetJSON(c *http.Client, url string, target any) error {
	r, err := c.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(target)
}

func PostJSON(c *http.Client, url string, dataStruct any) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(dataStruct); err != nil {
		return err
	}
	r, err := c.Post(url, "application/json", buf)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	_, err = io.ReadAll(r.Body)
	return err
}
