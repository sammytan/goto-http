//go:build linux

package logger

import (
	"syscall"
	"unsafe"
)

// GetTermios 获取终端属性
func GetTermios(fd uintptr) (*syscall.Termios, error) {
	termios := &syscall.Termios{}
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(termios)),
	)
	if err != 0 {
		return nil, err
	}
	return termios, nil
}
