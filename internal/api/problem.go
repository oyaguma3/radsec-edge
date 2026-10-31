package api

import (
	"encoding/json/v2"
	"errors"
	"net/http"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
)

// ProblemDetails の cause のうち、edge の誤り（edge.Cause*）のほかに API で使うもの（設計概要 §24.11）。
const (
	causeValidation          = "VALIDATION"
	causeIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	causeSystemFailure       = "SYSTEM_FAILURE"
	causeTenantNotFound      = "TENANT_NOT_FOUND"
	causeContainerNotFound   = "CONTAINER_NOT_FOUND"
	causeTenantBusy          = "TENANT_BUSY"
)

// busyRetryAfter は 503 TENANT_BUSY の Retry-After（秒）。
const busyRetryAfter = "5"

type invalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// problem はエラー応答（ProblemDetails。application/problem+json）。
type problem struct {
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail,omitempty"`
	Cause         string         `json:"cause,omitempty"`
	InvalidParams []invalidParam `json:"invalidParams,omitempty"`
}

func newProblem(status int, cause, detail string) *problem {
	return &problem{Title: http.StatusText(status), Status: status, Cause: cause, Detail: detail}
}

func badRequest(param, reason string) *problem {
	p := newProblem(http.StatusBadRequest, causeValidation, reason)
	p.InvalidParams = []invalidParam{{Param: param, Reason: reason}}
	return p
}

func (p *problem) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.MarshalWrite(w, p)
}

// statusOf は edge の誤りの符号から HTTP のステータスを決める。
func statusOf(cause string) int {
	switch cause {
	case edge.CauseSlugImmutable, edge.CauseCapacityExceeded, edge.CauseConflict:
		return http.StatusConflict
	}
	return http.StatusUnprocessableEntity
}

// fail は誤りを応答にする。利用者の誤りは理由の符号つきで返し、それ以外は記録して詳細を伏せた 500 を返す。
// 排他を取れないときは 503 にする（5xx は冪等の記録に残らないので、同じキーでやり直せる。§24.11 の EA7）。
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if ie, ok := errors.AsType[*edge.InputError](err); ok {
		cause := ie.Cause
		if cause == "" {
			cause = causeValidation
		}
		newProblem(statusOf(cause), cause, ie.Msg).write(w)
		return
	}
	switch {
	case errors.Is(err, db.ErrNotFound):
		newProblem(http.StatusNotFound, causeTenantNotFound, "テナント "+r.PathValue("tenantId")+" はありません").write(w)
	case errors.Is(err, agent.ErrNotFound):
		newProblem(http.StatusNotFound, causeContainerNotFound, "テナント "+r.PathValue("tenantId")+" のコンテナはありません").write(w)
	case errors.Is(err, edge.ErrBusy):
		w.Header().Set("Retry-After", busyRetryAfter)
		newProblem(http.StatusServiceUnavailable, causeTenantBusy, err.Error()).write(w)
	default:
		h.Log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		newProblem(http.StatusInternalServerError, causeSystemFailure, "").write(w)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, v)
}
