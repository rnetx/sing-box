package golang

import (
	"github.com/robertkrimen/otto"
)

func JSGoLog(jsVM *otto.Otto, logFunc func(args ...any)) func(otto.FunctionCall) otto.Value {
	return func(call otto.FunctionCall) otto.Value {
		if len(call.ArgumentList) == 0 {
			return otto.NullValue()
		}
		args := make([]any, 0, len(call.ArgumentList))
		for _, arg := range call.ArgumentList {
			item, err := arg.Export()
			if err == nil {
				if item == nil {
					args = append(args, "???")
				} else {
					args = append(args, item)
				}
			} else {
				args = append(args, "???")
			}
		}
		logFunc(args...)
		return otto.NullValue()
	}
}
