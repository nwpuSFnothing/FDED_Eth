`timescale 1 ns / 1 ps

module hot_digest_table #(
    parameter HOT_TABLE_DEPTH = 512,
    parameter HOT_ADDR_WIDTH  = 9
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] digest,
    output reg          done,
    output reg          hit
);

localparam [HOT_ADDR_WIDTH-1:0] HOT_TABLE_LAST = HOT_TABLE_DEPTH - 1;

(* ram_style = "block" *) reg [255:0] digest_mem [0:HOT_TABLE_DEPTH-1];
(* ram_style = "distributed" *) reg         valid_mem  [0:HOT_TABLE_DEPTH-1];
reg [HOT_ADDR_WIDTH-1:0] scan_addr;
reg running;

integer init_idx;

initial begin
    for (init_idx = 0; init_idx < HOT_TABLE_DEPTH; init_idx = init_idx + 1) begin
        digest_mem[init_idx] = 256'd0;
        valid_mem[init_idx] = 1'b0;
    end

    valid_mem[0] = 1'b1;
    digest_mem[0] = 256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;
end

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        done <= 1'b0;
        hit <= 1'b0;
        scan_addr <= {HOT_ADDR_WIDTH{1'b0}};
        running <= 1'b0;
    end else begin
        done <= 1'b0;

        if (start) begin
            hit <= 1'b0;
            scan_addr <= {HOT_ADDR_WIDTH{1'b0}};
            running <= 1'b1;
        end else if (running) begin
            if (valid_mem[scan_addr] && digest_mem[scan_addr] == digest)
                hit <= 1'b1;

            if (scan_addr == HOT_TABLE_LAST) begin
                running <= 1'b0;
                done <= 1'b1;
            end else begin
                scan_addr <= scan_addr + 1'b1;
            end
        end
    end
end

endmodule
