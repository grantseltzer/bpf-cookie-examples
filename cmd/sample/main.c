
void __attribute__ ((noinline)) stack_C() {            }
void __attribute__ ((noinline)) stack_B() { stack_C(); }
void __attribute__ ((noinline)) stack_A() { stack_B(); }
void main()                               { stack_A(); }
