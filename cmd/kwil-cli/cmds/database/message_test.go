package database

import (
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/types"
)

func Example_respDBlist_text_0() {
	display.Print(
		&respDBList{Info: []*types.DatasetIdentifier{}, owner: testOwner},
		nil, "text")
	// Output:
	// No databases found for '6f776e6572'.
}

func Example_respDBlist_text() {
	display.Print(
		&respDBList{Info: []*types.DatasetIdentifier{
			{
				Name:      "db_a",
				Owner:     testOwner,
				Namespace: "one",
			},
			{
				Name:      "db_b",
				Owner:     testOwner,
				Namespace: "two",
			},
		},
			owner: testOwner},
		nil, "text")
	// Output:
	// Databases belonging to '6f776e6572':
	//   Namespace: one
	//     Name: db_a
	//     Owner: 6f776e6572
	//   Namespace: two
	//     Name: db_b
	//     Owner: 6f776e6572
}

// hex.DecodeString("6f776e6572")
var testOwner = []byte{0x6f, 0x77, 0x6e, 0x65, 0x72}

func Example_respDBlist_json() {

	display.Print(
		&respDBList{Info: []*types.DatasetIdentifier{
			{
				Name:      "db_a",
				Owner:     testOwner,
				Namespace: "one",
			},
			{
				Name:      "db_b",
				Owner:     testOwner,
				Namespace: "two",
			},
		}},
		nil, "json")

	// Output:
	// {
	//   "result": [
	//     {
	//       "name": "db_a",
	//       "owner": "6f776e6572",
	//       "namespace": "one"
	//     },
	//     {
	//       "name": "db_b",
	//       "owner": "6f776e6572",
	//       "namespace": "two"
	//     }
	//   ],
	//   "error": ""
	// }
}

func Example_respRelations_text() {
	display.Print(&respRelations{
		Data: &types.QueryResult{
			ColumnNames: []string{"a", "b"},
			ColumnTypes: []*types.DataType{types.TextType, types.TextType},
			Values:      [][]any{{"1", "2"}, {"3", "4"}},
		},
	},
		nil, "text")
	// Output:
	// | a | b |
	// +---+---+
	// | 1 | 2 |
	// | 3 | 4 |
}

func Example_respRelations_json() {
	display.Print(&respRelations{
		Data: &types.QueryResult{
			ColumnNames: []string{"a", "b"},
			ColumnTypes: []*types.DataType{types.TextType, types.TextType},
			Values:      [][]any{{"1", "2"}, {"3", "4"}},
		},
	},
		nil, "json")
	// Output:
	// {
	//   "result": {
	//     "column_names": [
	//       "a",
	//       "b"
	//     ],
	//     "column_types": [
	//       {
	//         "name": "text",
	//         "is_array": false,
	//         "metadata": [
	//           0,
	//           0
	//         ]
	//       },
	//       {
	//         "name": "text",
	//         "is_array": false,
	//         "metadata": [
	//           0,
	//           0
	//         ]
	//       }
	//     ],
	//     "values": [
	//       [
	//         "1",
	//         "2"
	//       ],
	//       [
	//         "3",
	//         "4"
	//       ]
	//     ]
	//   },
	//   "error": ""
	// }
}
