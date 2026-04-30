`timescale 1 ns / 1 ps

module hot_digest_table #(
    parameter HOT_TABLE_DEPTH = 512,
    parameter HOT_ADDR_WIDTH  = 9
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] digest,
    input  wire         cfg_we,
    input  wire         cfg_clear,
    input  wire [HOT_ADDR_WIDTH-1:0] cfg_slot,
    input  wire [255:0] cfg_digest,
    output reg          done,
    output reg          hit
);

localparam [HOT_ADDR_WIDTH-1:0] HOT_TABLE_LAST = HOT_TABLE_DEPTH - 1;

(* ram_style = "block" *) reg [255:0] digest_mem [0:HOT_TABLE_DEPTH-1];
(* ram_style = "distributed" *) reg         valid_mem  [0:HOT_TABLE_DEPTH-1];
reg [HOT_ADDR_WIDTH-1:0] scan_addr;
reg running;
reg read_valid;
reg last_read_pending;
reg [255:0] query_digest;
reg [255:0] digest_rd;
reg valid_rd;

integer init_idx;

initial begin
    for (init_idx = 0; init_idx < HOT_TABLE_DEPTH; init_idx = init_idx + 1) begin
        valid_mem[init_idx] = 1'b0;
    end
end

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        done <= 1'b0;
        hit <= 1'b0;
        scan_addr <= {HOT_ADDR_WIDTH{1'b0}};
        running <= 1'b0;
        read_valid <= 1'b0;
        last_read_pending <= 1'b0;
        query_digest <= 256'd0;
        valid_rd <= 1'b0;
    end else begin
        done <= 1'b0;

        if (cfg_clear) begin
            for (init_idx = 0; init_idx < HOT_TABLE_DEPTH; init_idx = init_idx + 1)
                valid_mem[init_idx] <= 1'b0;
            hit <= 1'b0;
            scan_addr <= {HOT_ADDR_WIDTH{1'b0}};
            running <= 1'b0;
            read_valid <= 1'b0;
            last_read_pending <= 1'b0;
        end else if (cfg_we) begin
            valid_mem[cfg_slot] <= 1'b1;
        end else if (start) begin
            hit <= 1'b0;
            scan_addr <= {HOT_ADDR_WIDTH{1'b0}};
            running <= 1'b1;
            read_valid <= 1'b0;
            last_read_pending <= 1'b0;
            query_digest <= digest;
        end else if (running) begin
            valid_rd <= valid_mem[scan_addr];

            if (read_valid && valid_rd && digest_rd == query_digest)
                hit <= 1'b1;

            if (last_read_pending) begin
                running <= 1'b0;
                done <= 1'b1;
                read_valid <= 1'b0;
                last_read_pending <= 1'b0;
            end else begin
                read_valid <= 1'b1;
                if (scan_addr == HOT_TABLE_LAST) begin
                    last_read_pending <= 1'b1;
                end else begin
                    scan_addr <= scan_addr + 1'b1;
                end
            end
        end
    end
end

always @(posedge clk) begin
    if (cfg_we)
        digest_mem[cfg_slot] <= cfg_digest;

    digest_rd <= digest_mem[scan_addr];
end

endmodule
