package main

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"time"
	"unsafe"
)

type customType uint16

type nStruct struct {
	aBool  bool
	aInt   int
	aInt16 int16
}
type aStruct struct {
	aBool   bool
	aString string
	aNumber int
	nested  nestedStruct
}

type bStruct struct {
	aInt16 int16
	nested aStruct
	aBool  bool
	aInt32 int32
}

type cStruct struct {
	aInt32 int32
	aUint  uint
	nested structWithNoStrings
}

type structWithNoStrings struct {
	aUint8 uint8
	aBool  bool
}

type nestedStruct struct {
	anotherInt    int
	anotherString string
}

type anotherStruct struct {
	nested *nestedStruct
}

type tenStrings struct {
	first   string
	second  string
	third   string
	fourth  string
	fifth   string
	sixth   string
	seventh string
	eighth  string
	ninth   string
	tenth   string
}

type behavior interface {
	DoSomething()
}

type first_behavior struct {
	s string
}

type second_behavior struct {
	i int
}

func (b first_behavior) DoSomething() {
	fmt.Sprintln(b)
}

func (b second_behavior) DoSomething() {
	fmt.Sprintf("%10d\n", b.i)
}

// print_goroutine_id gets the goroutine ID and prints it
//
//go:noinline
func print_goroutine_id() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	fmt.Printf("%d\n", n)
	return n
}

/********************/
/* SINGLE PARAMETER */
/********************/

//go:noinline
func test_single_byte(x byte) {}

//go:noinline
func test_single_rune(x rune) {}

//go:noinline
func test_single_string(x string) {}

//go:noinline
func test_single_bool(x bool) {}

//go:noinline
func test_single_int(x int) {}

//go:noinline
func test_single_int8(x int8) {}

//go:noinline
func test_single_int16(x int16) {}

//go:noinline
func test_single_int32(x int32) {}

//go:noinline
func test_single_int64(x int64) {}

//go:noinline
func test_single_uint(x uint) {}

//go:noinline
func test_single_uint8(x uint8) {}

//go:noinline
func test_single_uint16(x uint16) {}

//go:noinline
func test_single_uint32(x uint32) {}

//go:noinline
func test_single_uint64(x uint64) {}

//go:noinline
func test_single_float32(x float32) {}

//go:noinline
func test_single_float64(x float64) {
}

/***********************/
/* Multiple Parameters */
/***********************/

//go:noinline
func test_combined_byte(w byte, x byte, y float32) {}

//go:noinline
func test_combined_rune(w byte, x rune, y float32) {}

//go:noinline
func test_combined_string(w byte, x string, y float32) {}

//go:noinline
func test_combined_bool(w byte, x bool, y float32) {}

//go:noinline
func test_combined_int(w byte, x int, y float32) {}

//go:noinline
func test_combined_int8(w byte, x int8, y float32) {}

//go:noinline
func test_combined_int16(w byte, x int16, y float32) {}

//go:noinline
func test_combined_int32(w byte, x int32, y float32) {}

//go:noinline
func test_combined_int64(w byte, x int64, y float32) {}

//go:noinline
func test_combined_uint(w byte, x uint, y float32) {}

//go:noinline
func test_combined_uint8(w byte, x uint8, y float32) {}

//go:noinline
func test_combined_uint16(w byte, x uint16, y float32) {}

//go:noinline
func test_combined_uint32(w byte, x uint32, y float32) {}

//go:noinline
func test_combined_uint64(w byte, x uint64, y float32) {}

/********************/
/* ARRAY PARAMETERs */
/********************/

//go:noinline
func test_byte_array(x [2]byte) {}

//go:noinline
func test_rune_array(x [2]rune) {}

//go:noinline
func test_string_array(x [2]string) {}

//go:noinline
func test_bool_array(x [2]bool) {}

//go:noinline
func test_int_array(x [2]int) {}

//go:noinline
func test_int8_array(x [2]int8) {}

//go:noinline
func test_int16_array(x [2]int16) {}

//go:noinline
func test_int32_array(x [2]int32) {}

//go:noinline
func test_int64_array(x [2]int64) {}

//go:noinline
func test_uint_array(x [2]uint) {}

//go:noinline
func test_uint8_array(x [2]uint8) {}

//go:noinline
func test_uint16_array(x [2]uint16) {}

//go:noinline
func test_uint32_array(x [2]uint32) {}

//go:noinline
func test_uint64_array(x [2]uint64) {}

//go:noinline
func test_struct(x aStruct) {}

//go:noinline
func test_nonembedded_struct(x nStruct) {}

//go:noinline
func test_multiple_embedded_struct(b bStruct) {}

//go:noinline
func test_no_string_struct(c cStruct) {}

//go:noinline
func test_struct_and_byte(w byte, x aStruct) {}

//go:noinline
func test_custom_type(c customType) {}

//go:noinline
func test_struct_pointer(x *aStruct) {}

//go:noinline
func test_nested_pointer(x *anotherStruct) {}

//go:noinline
func test_ten_strings(x tenStrings) {}

type iface struct {
	tab  *itab
	data unsafe.Pointer
}
type itab struct {
	inter uintptr
	_type uintptr
	hash  uint32
	_     [4]byte
	fun   [1]uintptr
}

//go:noinline
func test_interface(b behavior) {
	ptr := unsafe.Pointer(&b)
	iface := (*iface)(ptr)
	fmt.Printf("iface.tab.hash = %#x\n", iface.tab.hash)
}

//go:noinline
func test_struct_slice(xs []nestedStruct) {}

//go:noinline
func test_map_string_to_struct(m map[string]nestedStruct) {}

//go:noinline
func test_complex_types(a aStruct, c chan int, f func(), m map[int]int, p *int) {}

//go:noinline
func stack_A() {
	stack_B()
}

//go:noinline
func stack_B() {
	stack_C()
}

//go:noinline
func stack_C() {
	print("stacked")
}

func main() {
	for {
		stack_A()
		test_single_byte('a')
		test_single_rune('a')
		test_single_string("grant")
		test_single_bool(true)
		test_single_int(420)
		test_single_int8(1)
		test_single_int16(1)
		test_single_int32(1)
		test_single_int64(1)
		test_single_uint(1)
		test_single_uint8(1)
		test_single_uint16(1)
		test_single_uint32(1)
		test_single_uint64(42)
		test_single_float32(1.1)
		test_single_float64(1.1)
		test_combined_byte(2, 3, 3.0)
		test_combined_rune(2, 'b', 3.0)
		test_combined_string(2, "boo", 3.0)
		test_combined_bool(2, true, 3.0)
		test_combined_int(2, 3, 3.0)
		test_combined_int8(2, 38, 3.0)
		test_combined_int16(2, 316, 3.0)
		test_combined_int32(2, 332, 3.0)
		test_combined_int64(2, 364, 3.0)
		test_combined_uint(2, 12, 3.0)
		test_combined_uint8(2, 128, 3.0)
		test_combined_uint16(2, 1216, 3.0)
		test_combined_uint32(2, 1232, 3.0)
		test_combined_uint64(2, 1264, 3.0)
		test_byte_array([2]byte{3, 9})
		test_rune_array([2]rune{'a', 'b'})
		test_string_array([2]string{"boo", "bah"})
		test_bool_array([2]bool{true, true})
		test_int_array([2]int{5, 7})
		test_int8_array([2]int8{1, 5})
		test_int16_array([2]int16{166, 934})
		test_int32_array([2]int32{1325, 512})
		test_int64_array([2]int64{51, 77})
		test_uint_array([2]uint{1, 55})
		test_uint8_array([2]uint8{15, 55})
		test_uint16_array([2]uint16{951, 123})
		test_uint32_array([2]uint32{5135, 512321})
		test_uint64_array([2]uint64{412412456, 1234134})

		n := nStruct{false, 321333, 42}
		test_nonembedded_struct(n)

		s := aStruct{aBool: true, aString: "foo", aNumber: 42, nested: nestedStruct{anotherInt: 24, anotherString: "bar"}}
		test_struct(s)

		b := bStruct{aInt16: 42, nested: s, aBool: true, aInt32: 31}
		test_multiple_embedded_struct(b)

		ns := structWithNoStrings{aUint8: 9, aBool: true}
		cs := cStruct{aInt32: 4, aUint: 1, nested: ns}
		test_no_string_struct(cs)

		test_struct_pointer(&s)
		test_nested_pointer(&anotherStruct{&nestedStruct{anotherInt: 42, anotherString: "xyz"}})
		test_ten_strings(tenStrings{})
		test_struct_and_byte('a', s)
		test_custom_type(customType(3))

		test_interface(first_behavior{"foo"})
		test_interface(second_behavior{42})

		test_struct_slice([]nestedStruct{{42, "foo"}, {24, "bar"}})
		test_map_string_to_struct(map[string]nestedStruct{"foo": {1, "one"}, "bar": {2, "two"}})

		c := make(chan int)
		f := func() {}
		i := 4
		// a := [2]int{3, 4}
		test_complex_types(s, c, f, map[int]int{}, &i)
		go print_goroutine_id()
		time.Sleep(time.Second)
	}
}
