package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock:", err)
	}
	spec, err := loadSignal()
	if err != nil {
		log.Fatal("loadExechijack error", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"target_ppid": int32(400156),
	})
	if err != nil {
		log.Fatal("rewrite constants error,", err)
	}

	objs := signalObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatal("LoadAndAssign error,", err)
	}

	defer objs.Close()
	tp, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.BpfDos, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer tp.Close()
	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")
	go debug()
	var event signalEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("pid: %d\tcomm: %s\tsuccess:%t\n", event.Pid, unix.ByteSliceToString(event.Comm[:]), event.Success)
	}
}

func debug() {
	// 打开trace_pipe文件
	file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatalf("Failed to open trace_pipe: %v", err)
	}
	defer file.Close()

	// 使用bufio.Reader读取文件
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read from trace_pipe: %v", err)
		}

		// 打印从trace_pipe中读取的每一行
		fmt.Print(line)
	}
}
