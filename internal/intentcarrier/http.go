package intentcarrier

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type HTTPAuthorizer interface{ Authorize(string, bool) error }

func Handler(store *Store, authorize HTTPAuthorizer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/intents/admission-challenge", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), true) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		declared, err := strconv.ParseUint(request.URL.Query().Get("declared_bytes"), 10, 64)
		if err != nil {
			http.Error(writer, "invalid declared_bytes", http.StatusBadRequest)
			return
		}
		operationKind := request.URL.Query().Get("operation_kind")
		if operationKind == "" {
			operationKind = "publication.publish"
		}
		challenge, err := store.IssueAdmissionFor(operationKind, request.URL.Query().Get("actor_id"), request.URL.Query().Get("audience"), declared)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, http.StatusCreated, challenge)
	})
	mux.HandleFunc("POST /v1/intents/withdrawals", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), true) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, MaxStoredIntentBytes+(64<<10))
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input struct {
			Withdrawal commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
			Admission  commerce.OperationAdmissionProof     `json:"admission"`
			Action     commerce.AuthorizedAction            `json:"authorized_action"`
			Fence      commerce.WriterFence                 `json:"writer_fence"`
		}
		if decoder.Decode(&input) != nil || requireJSONEOF(decoder) != nil {
			http.Error(writer, "invalid admitted Intent withdrawal", http.StatusBadRequest)
			return
		}
		resolution, err := store.WithdrawAdmitted(input.Withdrawal, input.Admission, input.Action, input.Fence)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(writer, http.StatusCreated, struct {
			Resolution commerce.ActionResolution `json:"action_resolution"`
		}{resolution})
	})
	mux.HandleFunc("GET /v1/intents/{digest}", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), false) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		result, err := store.Get("sha256:" + request.PathValue("digest"))
		if errors.Is(err, os.ErrNotExist) {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	})
	mux.HandleFunc("POST /v1/intents", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), true) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, MaxStoredIntentBytes+(64<<10))
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var publication struct {
			Intent    commerce.SignedAgentIntent       `json:"intent"`
			Admission commerce.OperationAdmissionProof `json:"admission"`
			Action    commerce.AuthorizedAction        `json:"authorized_action"`
			Fence     commerce.WriterFence             `json:"writer_fence"`
		}
		if decoder.Decode(&publication) != nil || requireJSONEOF(decoder) != nil {
			http.Error(writer, "invalid admitted signed Intent", http.StatusBadRequest)
			return
		}
		result, resolution, err := store.PublishAdmitted(publication.Intent, publication.Admission, publication.Action, publication.Fence)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(writer, http.StatusCreated, struct {
			Result     Result                    `json:"result"`
			Resolution commerce.ActionResolution `json:"action_resolution"`
		}{result, resolution})
	})
	mux.HandleFunc("GET /v1/intent-actions/{action}", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), true) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		resolution, err := store.ResolveAction("sha256:"+request.PathValue("action"), request.URL.Query().Get("request_digest"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, http.StatusOK, resolution)
	})
	mux.HandleFunc("GET /v1/intents", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), false) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		query, err := parseQuery(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		page, err := store.Search(query)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, http.StatusOK, page)
	})
	mux.HandleFunc("GET /v1/intents/subscribe", func(writer http.ResponseWriter, request *http.Request) {
		if authorize == nil || authorize.Authorize(request.Header.Get("Authorization"), false) != nil {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		query, err := parseQuery(request)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		waitSeconds := uint64(20)
		if raw := request.URL.Query().Get("wait_seconds"); raw != "" {
			waitSeconds, err = strconv.ParseUint(raw, 10, 8)
			if err != nil || waitSeconds > 25 {
				http.Error(writer, "invalid wait_seconds", http.StatusBadRequest)
				return
			}
		}
		page, err := store.Subscribe(request.Context(), query, time.Duration(waitSeconds)*time.Second)
		if err != nil {
			http.Error(writer, "subscription interrupted", http.StatusRequestTimeout)
			return
		}
		writeJSON(writer, http.StatusOK, page)
	})
	return mux
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func parseQuery(request *http.Request) (Query, error) {
	values := request.URL.Query()
	limit := uint64(100)
	if values.Get("limit") != "" {
		parsed, err := strconv.ParseUint(values.Get("limit"), 10, 32)
		if err != nil {
			return Query{}, errors.New("invalid limit")
		}
		limit = parsed
	}
	var cursor uint64
	if raw := values.Get("cursor"); raw != "" {
		if !strings.HasPrefix(raw, "seq:") {
			return Query{}, errors.New("invalid cursor")
		}
		parsed, err := strconv.ParseUint(strings.TrimPrefix(raw, "seq:"), 10, 64)
		if err != nil || parsed == 0 {
			return Query{}, errors.New("invalid cursor")
		}
		cursor = parsed
	}
	query := Query{TaxonomyPrefix: values.Get("taxonomy_prefix"), Keywords: values["keyword"], Limit: uint32(limit), AfterCursor: cursor}
	for _, raw := range values["mode"] {
		query.Modes = append(query.Modes, commerce.IntentMode(strings.ToUpper(raw)))
	}
	for _, raw := range values["subject_class"] {
		query.SubjectClasses = append(query.SubjectClasses, commerce.SubjectClass(strings.ToUpper(raw)))
	}
	return query, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
