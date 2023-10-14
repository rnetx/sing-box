package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/robertkrimen/otto"
)

type httpRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	Body    string            `json:"body"`
	Timeout option.Duration   `json:"timeout"`
	Detour  string            `json:"detour"`
}

type httpResponse struct {
	Status  int
	Headers http.Header
	Body    string
	Cost    time.Duration
	Error   error
}

func JSGoHTTPRequests(ctx context.Context, jsVM *otto.Otto, httpClients map[string]*http.Client) func(call otto.FunctionCall) otto.Value {
	return func(call otto.FunctionCall) otto.Value {
		requestsArg := call.Argument(0)
		if !requestsArg.IsObject() {
			errStr, _ := jsVM.ToValue("requests must be an object")
			return errStr
		}

		requestsAny, err := requestsArg.Export()
		if err != nil {
			errStr, _ := jsVM.ToValue(E.Cause(err, "failed to parse requests").Error())
			return errStr
		}
		raw, err := json.Marshal(requestsAny)
		if err != nil {
			errStr, _ := jsVM.ToValue(E.Cause(err, "failed to parse requests").Error())
			return errStr
		}
		var requests []httpRequest
		err = json.Unmarshal(raw, &requests)
		if err != nil {
			errStr, _ := jsVM.ToValue(E.Cause(err, "failed to parse requests").Error())
			return errStr
		}
		for i := range requests {
			if requests[i].Method == "" {
				requests[i].Method = http.MethodGet
			}
			if requests[i].Detour == "" {
				errStr, _ := jsVM.ToValue("detour must not be empty")
				return errStr
			}
		}

		if len(requests) == 0 {
			errStr, _ := jsVM.ToValue("requests must not be empty")
			return errStr
		}

		var timeout time.Duration
		timeoutArg := call.Argument(1)
		if !timeoutArg.IsUndefined() {
			if timeoutArg.IsNumber() {
				n, _ := timeoutArg.ToInteger()
				timeout = time.Duration(n) * time.Second
			} else if timeoutArg.IsString() {
				s, _ := timeoutArg.ToString()
				if s != "" {
					d, err := time.ParseDuration(s)
					if err != nil {
						errStr, _ := jsVM.ToValue(E.Cause(err, "failed to parse timeout").Error())
						return errStr
					}
					timeout = d
				}
			} else {
				errStr, _ := jsVM.ToValue("timeout must be number or time string")
				return errStr
			}
		}

		ctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, timeout)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()

		responses := make([]httpResponse, len(requests))
		var responseLock sync.Mutex
		if len(requests) == 1 {
			request := requests[0]
			responses[0] = *httpRequestDo(ctx, httpClients[request.Detour], &request)
		} else {
			requestDone := make(chan struct{}, len(requests))
			for i, request := range requests {
				go func(index int, request httpRequest) {
					defer func() {
						requestDone <- struct{}{}
					}()
					response := httpRequestDo(ctx, httpClients[request.Detour], &request)
					responseLock.Lock()
					responses[index] = *response
					responseLock.Unlock()
				}(i, request)
			}
			for i := 0; i < len(requests); i++ {
				<-requestDone
			}
		}

		responsesJS, err := jsVM.Object(`(new Array())`)
		if err != nil {
			errStr, _ := jsVM.ToValue(E.Cause(err, "failed to create responses object").Error())
			return errStr
		}
		for _, response := range responses {
			responseJS, _ := jsVM.Object(`({})`)
			if response.Error != nil {
				responseJS.Set("error", response.Error.Error())
			} else {
				responseJS.Set("cost", response.Cost.Milliseconds())
				responseJS.Set("status", response.Status)
				if response.Headers != nil && len(response.Headers) > 0 {
					responseJS.Set("headers", response.Headers)
				}
				if response.Body != "" {
					responseJS.Set("body", response.Body)
				}
			}
			responsesJS.Call("push", responseJS)
		}

		return responsesJS.Value()
	}
}

func httpRequestDo(ctx context.Context, httpClient *http.Client, req *httpRequest) (resp *httpResponse) {
	resp = &httpResponse{}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		resp.Error = E.Cause(err, "failed to create http request")
		return
	}
	if req.Headers != nil && len(req.Headers) > 0 {
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}
	}
	if req.Cookies != nil && len(req.Cookies) > 0 {
		for key, value := range req.Cookies {
			httpReq.AddCookie(&http.Cookie{
				Name:  key,
				Value: value,
			})
		}
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.Timeout))
		defer cancel()
	}

	t := time.Now()
	httpResp, err := httpClient.Do(httpReq.WithContext(ctx))
	if err != nil {
		resp.Error = E.Cause(err, "failed to do http request")
		return
	}
	resp.Cost = time.Since(t)

	resp.Status = httpResp.StatusCode
	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, httpResp.Body)
	if err != nil {
		resp.Error = E.Cause(err, "failed to read http response body")
		return
	}

	if buffer.Len() > 0 {
		resp.Body = buffer.String()
	}
	resp.Headers = httpResp.Header

	return
}
