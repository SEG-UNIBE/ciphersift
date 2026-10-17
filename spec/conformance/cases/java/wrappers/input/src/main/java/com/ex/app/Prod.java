package com.ex.app;

class Prod {
    byte[] run(byte[] d) throws Exception {
        return AppTest.sha3(d); // AppTest is a test file: not a candidate for production code
    }
}
