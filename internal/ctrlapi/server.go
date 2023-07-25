package ctrlapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"io"
	"log"
	"net/http"
	"runtime"
)

var (
	muxSvr *http.ServeMux
)

func InitCtrlApiServer(svrPort int) error {
	if muxSvr != nil {
		return errors.New("cannot repeatedly init CtrlApiServer")
	}

	muxSvr = http.NewServeMux()
	muxSvr.HandleFunc("/stats", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		stats := libstats.GetStatsMgr()
		d, _ := json.Marshal(stats)
		_, writeErr := io.WriteString(writer, string(d))
		if writeErr != nil {
			log.Printf("io.WriteString failed, %v\n", writeErr)
		}
	})

	muxSvr.HandleFunc("/memstats", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		stats := libstats.CollectMemoryStatus()
		d, _ := json.Marshal(stats)
		_, writeErr := io.WriteString(writer, string(d))
		if writeErr != nil {
			log.Printf("io.WriteString failed, %v\n", writeErr)
		}
	})

	muxSvr.HandleFunc("/gc", func(writer http.ResponseWriter, request *http.Request) {
		runtime.GC()

		writer.Header().Set("Content-Type", "application/json")
		stats := libstats.CollectMemoryStatus()
		d, _ := json.Marshal(stats)
		_, writeErr := io.WriteString(writer, string(d))
		if writeErr != nil {
			log.Printf("io.WriteString failed, %v\n", writeErr)
		}
	})

	go func() {
		http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", svrPort), muxSvr)
	}()
	return nil
}
