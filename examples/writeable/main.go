package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var virtual_table_store = []map[string]string{
	{
		"property": "Name",
		"value":    "CyberSift",
	}, {
		"property": "Version",
		"value":    "0.1",
	},
}

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
	server.RegisterPlugin(table.NewWriteablePlugin("cybersift", FoobarColumns(), FoobarGenerate, FoobarInsert))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// FoobarColumns returns the columns that our table will return.
func FoobarColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("property"),
		table.TextColumn("value"),
	}
}

// FoobarGenerate will be called whenever the table is queried. It should return
// a full table scan.
func FoobarGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	log.Println(queryContext.Constraints)
	return virtual_table_store, nil
}

func FoobarInsert(ctx context.Context, valuesArray []interface{}) ([]map[string]string, error) {

	log.Println(valuesArray)
	virtual_table_store = append(virtual_table_store, map[string]string{
		"property": valuesArray[0].(string),
		"value":    valuesArray[1].(string),
	})

	return []map[string]string{
		{
			"status": "success",
			"id":     "123123123",
		},
	}, nil
}
