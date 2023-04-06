package main

type opcode uint8

const (
	OPCODE_NOP opcode = iota
	OPCODE_READ_REGISTER
	OPCODE_READ_STACK
	OPCODE_DEREFERENCE
	OPCODE_APPEND_TO_ARRAY
)

var opts_to_num_args = map[opcode]uint8{
	OPCODE_NOP:             0,
	OPCODE_READ_REGISTER:   1,
	OPCODE_READ_STACK:      2,
	OPCODE_DEREFERENCE:     3,
	OPCODE_APPEND_TO_ARRAY: 4,
}

type instruction struct {
	op opcode
	// _    [1]uint8 // padding
	arg2 uint8
	arg1 uint16
}

type instruction_set struct {
	instructions [MAX_INSTRUCTIONS]instruction
}

func create_dummy_cookie() instruction_set {
	return instruction_set{
		instructions: [MAX_INSTRUCTIONS]instruction{
			{
				op:   OPCODE_READ_REGISTER,
				arg1: 0,
			},
			{
				op: OPCODE_APPEND_TO_ARRAY,
			},
			{
				op:   OPCODE_READ_REGISTER,
				arg1: 1,
			},
			{
				op: OPCODE_APPEND_TO_ARRAY,
			},
			{
				op:   OPCODE_READ_REGISTER,
				arg1: 2,
			},
			{
				op: OPCODE_APPEND_TO_ARRAY,
			},
		},
	}
}
