package csv_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/csv"
)

func Test_CSV(t *testing.T) {
	file, err := loadTestCSV(t)
	if err != nil {
		t.Fatal(err)
	}

	data, err := csv.Read(file, csv.ContainsHeader)
	if err != nil {
		t.Fatal(err)
	}

	if len(data.Header) != 3 {
		t.Fatal(`expected 3 columns, got: `, len(data.Header))
	}
}

func Test_PrepareInputs(t *testing.T) {
	file, err := loadTestCSV(t)
	if err != nil {
		t.Fatal(err)
	}

	data, err := csv.Read(file, csv.ContainsHeader)
	if err != nil {
		t.Fatal(err)
	}

	inputNames := map[string]string{
		"id":        "$id",
		"full_name": "$name",
		"age":       "$age",
	}

	inputs, err := data.BuildInputs(inputNames)
	if err != nil {
		t.Fatal(err)
	}

	if len(inputs) != 100 {
		t.Fatal(`expected 100 records, got: `, len(inputs))
	}

	record := inputs[0]
	if len(record) != 3 {
		t.Fatal(`expected 3 columns, got: `, len(record))
	}

	row0col0 := record["$id"]
	row0col1 := record["$name"]
	row0col2 := record["$age"]

	if row0col0 != "1" {
		t.Fatal("expected row 0, column 0 to be 1, got: ", record[inputNames["$id"]])
	}

	if row0col1 != "Theodore Berry" {
		t.Fatal("expected row 0, column 1 to be Theodore Berry, got: ", record[inputNames["$name"]])
	}

	if row0col2 != "51" {
		t.Fatal("expected row 0, column 2 to be 51, got: ", record[inputNames["$age"]])
	}
}

func loadTestCSV(t *testing.T) (*os.File, error) {
	path := "./test.csv"
	return os.Open(path)
}

func loadCornCSV(t *testing.T) (*os.File, error) {
	path := "./corn.csv"
	return os.Open(path)
}

func Test_ReadDoubleQuotes(t *testing.T) {
	file, err := loadCornCSV(t)
	if err != nil {
		t.Fatal(err)
	}

	data, err := csv.Read(file, csv.ContainsHeader)
	if err != nil {
		t.Fatal(err)
	}

	inputNames := map[string]string{
		"Date":  "$dt",
		"Price": "$value",
	}

	res, err := data.BuildInputs(inputNames)
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 23 {
		t.Fatal(`expected 23 records, got: `, len(res))
	}

	if len(res[0]) != 2 {
		t.Fatal(`expected 2 columns, got: `, len(res[0]))
	}
}

func Test_JSON(t *testing.T) {
	jsonCsv, err := os.Open("./json.csv")
	if err != nil {
		t.Fatal(err)
	}

	c, err := csv.Read(jsonCsv, csv.ContainsHeader)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, c.Header, []string{"col1", "col2"})

	require.Equal(t, 1, len(c.Records))
	require.Equal(t, 2, len(c.Records[0]))
	require.Equal(t, "test", c.Records[0][0])
	require.Equal(t, `{"id":"6814e549-34f2-42db-9db3-61659b12708d","type":"human","level":"human","status":"approved"}`, c.Records[0][1])
}
