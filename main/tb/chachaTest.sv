`timescale 1ns/1ps
//============================================================================
// RFC 8439 compliance testbench for a single-block ChaCha20 core.
//
// Drives the core's exact ports: clk, rst_n, start, key[255:0], nonce[95:0],
// counter[31:0], plaintext[511:0] -> ciphertext[511:0], done, busy.
//
// PACKING CONVENTION (matches RFC little-endian word order):
//   byte i of every stream sits at bit [8*i +: 8].
//   So key[31:0] holds the first 4 key bytes, low byte first; output byte i
//   is read from ciphertext[8*i +: 8]. The vectors below are pre-packed this way.
//
// Vectors are the official RFC 8439 examples:
//   KAT1 = section 2.3.2 block function (keystream, zero plaintext)
//   KAT2 = section 2.4.2 cipher, first 64-byte block (counter = 1)
//============================================================================
module tb_chacha20_compliance;

    reg          clk = 0, rst_n = 0, start = 0;
    reg  [255:0] key;
    reg  [95:0]  nonce;
    reg  [31:0]  counter;
    reg  [511:0] plaintext;
    wire [511:0] ciphertext;
    wire         done, busy;

    ChaCha20 dut (
        .clk(clk), .rst_n(rst_n), .start(start),
        .key(key), .nonce(nonce), .counter(counter),
        .plaintext(plaintext), .ciphertext(ciphertext),
        .done(done), .busy(busy)
    );

    always #5 clk = ~clk;

    // ---- RFC 8439 vectors (pre-packed: byte i at bit 8*i) ----
    localparam [255:0] KEY  = 256'h1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100;
    localparam [95:0]  NON1 = 96'h000000004a00000009000000;
    localparam [95:0]  NON2 = 96'h000000004a00000000000000;
    localparam [511:0] PT2  = 512'h6f20756f7920726566666f20646c756f632049206649203a39392720666f207373616c632065687420666f206e656d656c746e654720646e612073656964614c;
    localparam [511:0] EXP1 = 512'h4e3c50a2e883d0cbb94e16ded19c12b5a2028bd905d7c21409aa9f07466482d24e6cd4c39aaa22040368c033c7f4d1c7c47120a31fdd0f5015593bd1e4e7f110;
    localparam [511:0] EXP2 = 512'hd861089f350c538fab5251e624d6391657b362cdab3d598fab334752c5651bf90bae9ffdccaf270ac260431dec7a7ee981690ddd2807ba4180f968259a352e6e;

    integer tests = 0, passes = 0;
    integer b;

    task run_kat;
        input [8*32-1:0] name;
        input [255:0]    k;
        input [95:0]     n;
        input [31:0]     c;
        input [511:0]    pt;
        input [511:0]    exp;
        begin
            @(negedge clk);
            key = k; nonce = n; counter = c; plaintext = pt;
            start = 1; @(negedge clk); start = 0;
            wait (done); @(negedge clk);

            tests = tests + 1;
            if (ciphertext === exp) begin
                passes = passes + 1;
                $display("[PASS] %0s", name);
            end else begin
                $display("[FAIL] %0s", name);
                $display("       expected: %h", exp);
                $display("       got     : %h", ciphertext);
                // byte-level diff to localize the problem
                for (b = 0; b < 64; b = b + 1)
                    if (ciphertext[8*b +: 8] !== exp[8*b +: 8])
                        $display("       byte %0d: exp %02h got %02h",
                                 b, exp[8*b +: 8], ciphertext[8*b +: 8]);
            end
            wait (!done); // let the FSM return to IDLE before the next vector
        end
    endtask

    initial begin
        $dumpfile("chacha20_compliance.vcd");
        $dumpvars(0, tb_chacha20_compliance);

        rst_n = 0; repeat (4) @(negedge clk);
        rst_n = 1; @(negedge clk);

        $display("=== RFC 8439 ChaCha20 compliance ===");
        run_kat("KAT1 RFC 2.3.2 block function", KEY, NON1, 32'd1, 512'h0, EXP1);
        run_kat("KAT2 RFC 2.4.2 cipher block 1", KEY, NON2, 32'd1, PT2,    EXP2);

        $display("------------------------------------");
        $display("%0d/%0d vectors passed", passes, tests);
        if (passes == tests) $display("RESULT: COMPLIANT");
        else                 $display("RESULT: NON-COMPLIANT");
        $finish;
    end
endmodule