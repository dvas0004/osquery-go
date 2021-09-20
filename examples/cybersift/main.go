package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"syscall"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"

	"github.com/shirou/gopsutil/v3/process"
)

var virtual_table_store = []map[string]string{}

func main() {
	socket := flag.String("socket", "", "Path to osquery socket file")
	verbose := flag.Bool("verbose", false, "Verbose")
	timeout := flag.Int("timeout", 0, "timeout")
	interval := flag.Int("interval", 0, "interval")

	flag.Parse()

	if *timeout > 0 {
		log.Println("Timeout set to " + strconv.Itoa(*timeout))
	}

	if *interval > 0 {
		log.Println("Interval set to " + strconv.Itoa(*interval))
	}

	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	if *verbose {
		log.Println("Verbose set to true")
	}

	server, err := osquery.NewExtensionManagerServer("cybersift", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewWriteablePlugin("cybersift", GenerateColumns(), GenerateTable, FoobarInsert))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// GenerateColumns returns the columns that our table will return.
func GenerateColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("pid"),
	}
}

// GenerateTable will be called whenever the table is queried. It should return
// a full table scan.
func GenerateTable(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	log.Println(queryContext.Constraints)

	virtual_table_store = []map[string]string{}

	running_processses, _ := process.Processes()
	for _, proc := range running_processses {
		name, _ := proc.Name()
		pid := proc.Pid

		virtual_table_store = append(virtual_table_store, map[string]string{
			"name": name,
			"pid":  strconv.Itoa(int(pid)),
		})

	}

	return virtual_table_store, nil
}

func FoobarInsert(ctx context.Context, valuesArray []interface{}) ([]map[string]string, error) {

	log.Println(valuesArray)
	pidNumerical, _ := strconv.Atoi(valuesArray[1].(string))
	syscall.Kill(pidNumerical, 9)

	return []map[string]string{
		{
			"status": "success",
			"id":     "123123123",
		},
	}, nil
}
