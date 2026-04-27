`timescale 1 ns / 1 ps

module udp_sha256_oneblock (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [15:0]  payload_len,
    output reg  [10:0]  ram_read_addr,
    input  wire [7:0]   ram_read_data,
    output reg  [255:0] digest,
    output reg          done,
    output reg          error,
    output reg          busy
);

localparam ST_IDLE        = 3'd0;
localparam ST_READ_SETUP  = 3'd1;
localparam ST_READ_DATA   = 3'd2;
localparam ST_BUILD_BLOCK = 3'd3;
localparam ST_WAIT_READY  = 3'd4;
localparam ST_SHA_START   = 3'd5;
localparam ST_WAIT_DIGEST = 3'd6;

reg [2:0] state;
reg [15:0] payload_len_reg;
reg [6:0] read_index;
reg [511:0] sha_block;
reg sha_valid;
reg [7:0] payload_buf [0:54];

wire [255:0] sha_digest;
wire sha_digest_valid;
wire sha_ready;

integer i;

sha256_stream sha256_stream_inst (
    .clk(clk),
    .rst(~rst_n),
    .mode(1'b1),
    .s_tdata_i(sha_block),
    .s_tlast_i(1'b1),
    .s_tvalid_i(sha_valid),
    .s_tready_o(sha_ready),
    .digest_o(sha_digest),
    .digest_valid_o(sha_digest_valid)
);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= ST_IDLE;
        payload_len_reg <= 16'd0;
        read_index <= 7'd0;
        ram_read_addr <= 11'd0;
        sha_block <= 512'd0;
        sha_valid <= 1'b0;
        digest <= 256'd0;
        done <= 1'b0;
        error <= 1'b0;
        busy <= 1'b0;
        for (i = 0; i < 55; i = i + 1) begin
            payload_buf[i] <= 8'd0;
        end
    end else begin
        done <= 1'b0;
        sha_valid <= 1'b0;

        case (state)
            ST_IDLE: begin
                busy <= 1'b0;
                error <= 1'b0;
                ram_read_addr <= 11'd0;

                if (start) begin
                    if (payload_len <= 16'd55) begin
                        busy <= 1'b1;
                        payload_len_reg <= payload_len;
                        read_index <= 7'd0;
                        ram_read_addr <= 11'd0;
                        if (payload_len == 16'd0) begin
                            state <= ST_BUILD_BLOCK;
                        end else begin
                            state <= ST_READ_SETUP;
                        end
                    end else begin
                        digest <= 256'd0;
                        error <= 1'b1;
                        done <= 1'b1;
                    end
                end
            end

            ST_READ_SETUP: begin
                state <= ST_READ_DATA;
            end

            ST_READ_DATA: begin
                payload_buf[read_index] <= ram_read_data;
                if (read_index + 1 < payload_len_reg) begin
                    read_index <= read_index + 1'b1;
                    ram_read_addr <= read_index + 1'b1;
                end else begin
                    state <= ST_BUILD_BLOCK;
                end
            end

            ST_BUILD_BLOCK: begin
                sha_block <= 512'd0;

                for (i = 0; i < 55; i = i + 1) begin
                    if (i < payload_len_reg) begin
                        sha_block[511 - (i * 8) -: 8] <= payload_buf[i];
                    end
                end

                sha_block[511 - (payload_len_reg * 8) -: 8] <= 8'h80;
                sha_block[63:0] <= {48'd0, payload_len_reg} << 3;
                state <= ST_WAIT_READY;
            end

            ST_WAIT_READY: begin
                if (sha_ready) begin
                    state <= ST_SHA_START;
                end
            end

            ST_SHA_START: begin
                sha_valid <= 1'b1;
                state <= ST_WAIT_DIGEST;
            end

            ST_WAIT_DIGEST: begin
                if (sha_digest_valid) begin
                    digest <= sha_digest;
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= ST_IDLE;
                end
            end

            default: begin
                state <= ST_IDLE;
            end
        endcase
    end
end

endmodule
