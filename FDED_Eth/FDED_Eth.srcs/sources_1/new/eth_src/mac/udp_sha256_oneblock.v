`timescale 1 ns / 1 ps

module udp_sha256_oneblock (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [15:0]  payload_len,
    output reg  [10:0]  ram_read_addr,
    input  wire [7:0]   ram_read_data,
    output reg  [31:0]  seq_id,
    output reg  [255:0] digest,
    output reg          hot_hit,
    output reg          done,
    output reg          error,
    output reg          busy
);

localparam ST_IDLE            = 4'd0;
localparam ST_READ_SETUP      = 4'd1;
localparam ST_READ_DATA       = 4'd2;
localparam ST_PREP_BLOCK      = 4'd3;
localparam ST_BUILD_BLOCK     = 4'd4;
localparam ST_WAIT_READY      = 4'd5;
localparam ST_SHA_START       = 4'd6;
localparam ST_WAIT_BLOCK_DONE = 4'd7;
localparam ST_HOT_LOOKUP_WAIT = 4'd8;

localparam READ_SEQ   = 1'b0;
localparam READ_BLOCK = 1'b1;

reg  [3:0]   state;
reg  [15:0]  hash_payload_len_reg;
reg  [15:0]  full_blocks_reg;
reg  [15:0]  block_index_reg;
reg  [6:0]   final_bytes_reg;
reg  [6:0]   read_count_reg;
reg  [6:0]   read_index;
reg          read_mode_reg;
reg          block_is_last_reg;
reg  [511:0] sha_block;
reg          sha_valid;
reg          sha_last;
reg          sha_digest_valid_d0;
reg          hot_lookup_start;

wire [255:0] sha_digest;
wire         sha_digest_valid;
wire         sha_ready;
wire [63:0]  hash_bit_len;
wire         hot_lookup_done;
wire         hot_lookup_hit;

assign hash_bit_len = {45'd0, hash_payload_len_reg, 3'b000};

sha256_stream sha256_stream_inst (
    .clk(clk),
    .rst(~rst_n),
    .mode(1'b1),
    .s_tdata_i(sha_block),
    .s_tlast_i(sha_last),
    .s_tvalid_i(sha_valid),
    .s_tready_o(sha_ready),
    .digest_o(sha_digest),
    .digest_valid_o(sha_digest_valid)
);

hot_digest_table #(
    .HOT_TABLE_DEPTH(512),
    .HOT_ADDR_WIDTH(9)
) hot_digest_table_inst (
    .clk(clk),
    .rst_n(rst_n),
    .start(hot_lookup_start),
    .digest(digest),
    .done(hot_lookup_done),
    .hit(hot_lookup_hit)
);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= ST_IDLE;
        hash_payload_len_reg <= 16'd0;
        full_blocks_reg <= 16'd0;
        block_index_reg <= 16'd0;
        final_bytes_reg <= 7'd0;
        read_count_reg <= 7'd0;
        read_index <= 7'd0;
        read_mode_reg <= READ_SEQ;
        block_is_last_reg <= 1'b0;
        ram_read_addr <= 11'd0;
        seq_id <= 32'd0;
        sha_block <= 512'd0;
        sha_valid <= 1'b0;
        sha_last <= 1'b0;
        sha_digest_valid_d0 <= 1'b0;
        hot_lookup_start <= 1'b0;
        digest <= 256'd0;
        hot_hit <= 1'b0;
        done <= 1'b0;
        error <= 1'b0;
        busy <= 1'b0;
    end else begin
        done <= 1'b0;
        sha_valid <= 1'b0;
        hot_lookup_start <= 1'b0;
        sha_digest_valid_d0 <= sha_digest_valid;

        case (state)
            ST_IDLE: begin
                busy <= 1'b0;
                error <= 1'b0;
                ram_read_addr <= 11'd0;
                block_index_reg <= 16'd0;

                if (start) begin
                    if (payload_len >= 16'd4 && payload_len <= 16'd2048) begin
                        busy <= 1'b1;
                        hash_payload_len_reg <= payload_len - 16'd4;
                        full_blocks_reg <= (payload_len - 16'd4) >> 6;
                        final_bytes_reg <= (payload_len - 16'd4) & 16'h003f;
                        read_count_reg <= 7'd4;
                        read_index <= 7'd0;
                        read_mode_reg <= READ_SEQ;
                        block_is_last_reg <= 1'b0;
                        ram_read_addr <= 11'd0;
                        seq_id <= 32'd0;
                        digest <= 256'd0;
                        hot_hit <= 1'b0;
                        sha_block <= 512'd0;
                        sha_last <= 1'b0;
                        state <= ST_READ_SETUP;
                    end else begin
                        seq_id <= 32'd0;
                        digest <= 256'd0;
                        hot_hit <= 1'b0;
                        error <= 1'b1;
                        done <= 1'b1;
                    end
                end
            end

            ST_READ_SETUP: begin
                state <= ST_READ_DATA;
            end

            ST_READ_DATA: begin
                if (read_mode_reg == READ_SEQ) begin
                    case (read_index)
                        7'd0: seq_id[31:24] <= ram_read_data;
                        7'd1: seq_id[23:16] <= ram_read_data;
                        7'd2: seq_id[15:8]  <= ram_read_data;
                        default: seq_id[7:0] <= ram_read_data;
                    endcase
                end else begin
                    sha_block[511 - (read_index * 8) -: 8] <= ram_read_data;
                end

                if (read_index + 1 < read_count_reg) begin
                    read_index <= read_index + 1'b1;
                    ram_read_addr <= ram_read_addr + 1'b1;
                    state <= ST_READ_SETUP;
                end else if (read_mode_reg == READ_SEQ) begin
                    state <= ST_PREP_BLOCK;
                end else begin
                    state <= ST_BUILD_BLOCK;
                end
            end

            ST_PREP_BLOCK: begin
                sha_block <= 512'd0;

                if (block_index_reg < full_blocks_reg) begin
                    read_mode_reg <= READ_BLOCK;
                    read_count_reg <= 7'd64;
                    read_index <= 7'd0;
                    block_is_last_reg <= 1'b0;
                    ram_read_addr <= 11'd4 + (block_index_reg << 6);
                    state <= ST_READ_SETUP;
                end else if (final_bytes_reg < 7'd56) begin
                    block_is_last_reg <= 1'b1;
                    if (final_bytes_reg != 7'd0) begin
                        read_mode_reg <= READ_BLOCK;
                        read_count_reg <= final_bytes_reg;
                        read_index <= 7'd0;
                        ram_read_addr <= 11'd4 + (full_blocks_reg << 6);
                        state <= ST_READ_SETUP;
                    end else begin
                        read_count_reg <= 7'd0;
                        state <= ST_BUILD_BLOCK;
                    end
                end else if (block_index_reg == full_blocks_reg) begin
                    read_mode_reg <= READ_BLOCK;
                    read_count_reg <= final_bytes_reg;
                    read_index <= 7'd0;
                    block_is_last_reg <= 1'b0;
                    ram_read_addr <= 11'd4 + (full_blocks_reg << 6);
                    state <= ST_READ_SETUP;
                end else begin
                    read_count_reg <= 7'd0;
                    block_is_last_reg <= 1'b1;
                    state <= ST_BUILD_BLOCK;
                end
            end

            ST_BUILD_BLOCK: begin
                if (block_index_reg >= full_blocks_reg) begin
                    if (final_bytes_reg < 7'd56) begin
                        sha_block[511 - (final_bytes_reg * 8) -: 8] <= 8'h80;
                        sha_block[63:0] <= hash_bit_len;
                    end else if (block_index_reg == full_blocks_reg) begin
                        sha_block[511 - (final_bytes_reg * 8) -: 8] <= 8'h80;
                    end else begin
                        sha_block[63:0] <= hash_bit_len;
                    end
                end

                state <= ST_WAIT_READY;
            end

            ST_WAIT_READY: begin
                if (sha_ready) begin
                    state <= ST_SHA_START;
                end
            end

            ST_SHA_START: begin
                sha_valid <= 1'b1;
                sha_last <= block_is_last_reg;
                state <= ST_WAIT_BLOCK_DONE;
            end

            ST_WAIT_BLOCK_DONE: begin
                if (sha_digest_valid && ~sha_digest_valid_d0) begin
                    if (block_is_last_reg) begin
                        digest <= sha_digest;
                        hot_lookup_start <= 1'b1;
                        state <= ST_HOT_LOOKUP_WAIT;
                    end else begin
                        block_index_reg <= block_index_reg + 1'b1;
                        state <= ST_PREP_BLOCK;
                    end
                end
            end

            ST_HOT_LOOKUP_WAIT: begin
                if (hot_lookup_done) begin
                    hot_hit <= hot_lookup_hit;
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
