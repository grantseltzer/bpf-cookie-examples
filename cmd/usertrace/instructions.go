package main

type opcode uint8

const (
	OPCODE_INVALID_INSTRUCTION opcode = iota
	OPCODE_READ_REGISTER
	OPCODE_READ_STACK
	OPCODE_DEREFERENCE
	OPCODE_APPEND_TO_ARRAY
)

var opts_to_num_args = map[opcode]uint8{
	OPCODE_READ_REGISTER:   1,
	OPCODE_READ_STACK:      2,
	OPCODE_DEREFERENCE:     0,
	OPCODE_APPEND_TO_ARRAY: 0,
}

type instruction struct {
	op   opcode
	arg1 uint64
	arg2 uint64
}

func encode_cookie(c []instruction) []uint64 {

	out := []uint64{}

	for _, x := range c {

		out = append(out, uint64(x.op))

		switch opts_to_num_args[x.op] {
		case 1:
			out = append(out, uint64(x.arg1))
		case 2:
			out = append(out, uint64(x.arg1))
			out = append(out, uint64(x.arg2))
		}
	}
	return out
}

func create_dummy_cookie() []instruction {
	return []instruction{
		{
			op:   OPCODE_READ_REGISTER,
			arg1: 0,
		},
		{
			op: OPCODE_APPEND_TO_ARRAY,
		},
	}
}
