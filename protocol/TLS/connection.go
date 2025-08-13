package tls

import (
    "bufio"
    "fmt"
    "net"
    "sync"
)

type MessageHandler interface {
    HandleMessage(data []byte) error
}

// ConnectionManager manages read/write loops for connections
type ConnectionManager struct {
    conn    net.Conn
    handler MessageHandler
    wg      sync.WaitGroup
    done    chan struct{}
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(conn net.Conn, handler MessageHandler) *ConnectionManager {
    return &ConnectionManager{
        conn:    conn,
        handler: handler,
        done:    make(chan struct{}),
    }
}

// StartReadLoop starts the read loop in a goroutine
func (cm *ConnectionManager) StartReadLoop() {
    cm.wg.Add(1)
    go cm.readLoop()
}

// StartWriteLoop starts the write loop in a goroutine
func (cm *ConnectionManager) StartWriteLoop(writeChannel <-chan []byte) {
    cm.wg.Add(1)
    go cm.writeLoop(writeChannel)
}

// readLoop handles incoming messages from the connection
func (cm *ConnectionManager) readLoop() {
    defer cm.wg.Done()
    defer cm.conn.Close()

    scanner := bufio.NewScanner(cm.conn)
    for scanner.Scan() {
        select {
        case <-cm.done:
            return
        default:
            data := scanner.Bytes()
            if len(data) > 0 {
                if err := cm.handler.HandleMessage(data); err != nil {
                    fmt.Printf("Error handling message: %v\n", err)
                    return
                }
            }
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Read error: %v\n", err)
    }
}

// writeLoop handles outgoing messages to the connection
func (cm *ConnectionManager) writeLoop(writeChannel <-chan []byte) {
    defer cm.wg.Done()
    defer cm.conn.Close()

    for {
        select {
        case <-cm.done:
            return
        case data, ok := <-writeChannel:
            if !ok {
                return
            }
            if _, err := cm.conn.Write(data); err != nil {
                fmt.Printf("Write error: %v\n", err)
                return
            }
        }
    }
}

// Stop gracefully stops the connection manager
func (cm *ConnectionManager) Stop() {
    close(cm.done)
}

// Wait waits for all goroutines to finish
func (cm *ConnectionManager) Wait() {
    cm.wg.Wait()
}

// Close closes the connection and stops all loops
func (cm *ConnectionManager) Close() {
    cm.Stop()
    cm.conn.Close()
    cm.Wait()
}