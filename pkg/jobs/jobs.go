// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package jobs

import (
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/mux"

	"github.com/pmd-nextgen/pkg/web"
)

type Result struct {
	Output interface{}
	Err    error
}

type Job struct {
	ResultChannel chan Result
	Id            uint64
}

type Jobs struct {
	jobMap     map[uint64]Job
	resultMap  map[uint64]Result
	jobCounter uint64
	Mutex      *sync.Mutex
}

var jobs *Jobs

func New() *Jobs {
	if jobs != nil {
		return jobs
	} else {
		jobs = &Jobs{
			jobMap:    make(map[uint64]Job),
			resultMap: make(map[uint64]Result),
			Mutex:     &sync.Mutex{},
		}
		return jobs
	}
}

func NewJob() *Job {
	jobs.Mutex.Lock()
	defer jobs.Mutex.Unlock()

	jobs.jobCounter++
	job := Job{
		ResultChannel: make(chan Result),
		Id:            jobs.jobCounter,
	}

	jobs.jobMap[jobs.jobCounter] = job

	return &job
}

func RemoveJob(id uint64) {
	jobs.Mutex.Lock()
	defer jobs.Mutex.Unlock()

	delete(jobs.jobMap, id)
}

func RemoveResult(id uint64) {
	jobs.Mutex.Lock()
	defer jobs.Mutex.Unlock()

	delete(jobs.resultMap, id)
}

func CreateJob(acquireFunc func() (interface{}, error)) *Job {
	job := NewJob()
	go func() {
		s, err := acquireFunc()
		result := Result{
			Output: s,
			Err:    err,
		}
		job.ResultChannel <- result
	}()
	return job
}

func AcceptedResponse(w http.ResponseWriter, job *Job) error {
	w.Header().Set("Location", "/api/v1/_jobs/status/"+strconv.FormatUint(job.Id, 10))
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func routerAcquireStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		web.JSONResponseError(errors.New("invalid id"), w)
	}
	if job, ok := jobs.jobMap[id]; ok {
		select {
		case result := <-job.ResultChannel:
			jobs.resultMap[id] = result
			RemoveJob(id)
			web.JSONResponse(
				web.StatusResponse{
					Status: "complete",
					Link:   "/api/v1/_jobs/result/" + strconv.FormatUint(id, 10),
				},
				w)
		default:
			web.JSONResponse(web.StatusResponse{Status: "inprogress"}, w)
		}
	} else {
		web.JSONResponseError(errors.New("not found"), w)
	}
}

func routerAcquireResult(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		web.JSONResponseError(errors.New("invalid id"), w)
	}
	if result, ok := jobs.resultMap[id]; ok {
		if result.Err != nil {
			web.JSONResponseError(result.Err, w)
		} else {
			web.JSONResponse(result.Output, w)
		}
		RemoveResult(id)
	} else {
		web.JSONResponseError(errors.New("not found"), w)
	}
}

func RegisterRouterJobs(router *mux.Router) {
	jobs = New()

	n := router.PathPrefix("/_jobs").Subrouter().StrictSlash(false)

	n.HandleFunc("/status/{id}", routerAcquireStatus).Methods("GET")
	n.HandleFunc("/result/{id}", routerAcquireResult).Methods("GET")
}
