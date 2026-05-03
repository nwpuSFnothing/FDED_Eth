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
    output reg          stream_ack,
    output reg          done,
    output reg          error,
    output reg          busy
);

localparam ST_IDLE                  = 5'd0;
localparam ST_READ_SETUP            = 5'd1;
localparam ST_READ_DATA             = 5'd2;
localparam ST_PREP_BLOCK            = 5'd3;
localparam ST_BUILD_BLOCK           = 5'd4;
localparam ST_WAIT_READY            = 5'd5;
localparam ST_SHA_START             = 5'd6;
localparam ST_WAIT_BLOCK_DONE       = 5'd7;
localparam ST_HOT_LOOKUP_WAIT       = 5'd8;
localparam ST_CTRL_OP_SETUP         = 5'd9;
localparam ST_CTRL_OP_READ          = 5'd10;
localparam ST_CTRL_DATA_SETUP       = 5'd11;
localparam ST_CTRL_DATA_READ        = 5'd12;
localparam ST_CTRL_APPLY            = 5'd13;
localparam ST_CTRL_DONE             = 5'd14;
localparam ST_STREAM_HDR_SETUP      = 5'd15;
localparam ST_STREAM_HDR_READ       = 5'd16;
localparam ST_STREAM_DATA_SETUP     = 5'd17;
localparam ST_STREAM_DATA_READ      = 5'd18;
localparam ST_STREAM_WAIT_READY     = 5'd19;
localparam ST_STREAM_SHA_START      = 5'd20;
localparam ST_STREAM_WAIT_BLOCK     = 5'd21;
localparam ST_STREAM_FINISH_PACKET  = 5'd22;
localparam ST_STREAM_FINAL_PREP     = 5'd23;
localparam ST_STREAM_FINAL_WAIT     = 5'd24;
localparam ST_STREAM_FINAL_START    = 5'd25;
localparam ST_STREAM_FINAL_BLOCK    = 5'd26;

localparam READ_SEQ   = 1'b0;
localparam READ_BLOCK = 1'b1;
localparam [31:0] CTRL_MAGIC = 32'h46444544; // "FDED"
localparam [7:0]  CTRL_WRITE_SLOT = 8'h10;
localparam [7:0]  CTRL_CLEAR      = 8'h11;
localparam [7:0]  CTRL_STREAM_START = 8'h20;
localparam [7:0]  CTRL_STREAM_DATA  = 8'h21;
localparam [7:0]  CTRL_STREAM_END   = 8'h22;

reg  [4:0]   state;
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
reg          hot_cfg_we;
reg          hot_cfg_clear;
reg  [8:0]   hot_cfg_slot;
reg  [255:0] hot_cfg_digest;
reg  [7:0]   ctrl_op_reg;
reg  [15:0]  ctrl_slot_reg;
reg          stream_active;
reg          stream_finalizing;
reg          stream_need_len_block;
reg          stream_final_second;
reg  [31:0]  stream_id_reg;
reg  [31:0]  ctrl_stream_id_reg;
reg  [31:0]  stream_total_len_reg;
reg  [31:0]  ctrl_stream_total_len_reg;
reg  [31:0]  stream_bytes_seen_reg;
reg  [15:0]  stream_packet_data_len_reg;
reg  [15:0]  stream_packet_read_idx_reg;
reg  [5:0]   stream_partial_len_reg;
reg  [511:0] stream_partial_block;

wire [255:0] sha_digest;
wire         sha_digest_valid;
wire         sha_ready;
wire [63:0]  hash_bit_len;
wire [63:0]  stream_bit_len;
wire         hot_lookup_done;
wire         hot_lookup_hit;

assign hash_bit_len = {45'd0, hash_payload_len_reg, 3'b000};
assign stream_bit_len = {29'd0, stream_total_len_reg, 3'b000};

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
    .cfg_we(hot_cfg_we),
    .cfg_clear(hot_cfg_clear),
    .cfg_slot(hot_cfg_slot),
    .cfg_digest(hot_cfg_digest),
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
        hot_cfg_we <= 1'b0;
        hot_cfg_clear <= 1'b0;
        hot_cfg_slot <= 9'd0;
        hot_cfg_digest <= 256'd0;
        ctrl_op_reg <= 8'd0;
        ctrl_slot_reg <= 16'd0;
        stream_active <= 1'b0;
        stream_finalizing <= 1'b0;
        stream_need_len_block <= 1'b0;
        stream_final_second <= 1'b0;
        stream_id_reg <= 32'd0;
        ctrl_stream_id_reg <= 32'd0;
        stream_total_len_reg <= 32'd0;
        ctrl_stream_total_len_reg <= 32'd0;
        stream_bytes_seen_reg <= 32'd0;
        stream_packet_data_len_reg <= 16'd0;
        stream_packet_read_idx_reg <= 16'd0;
        stream_partial_len_reg <= 6'd0;
        stream_partial_block <= 512'd0;
        digest <= 256'd0;
        hot_hit <= 1'b0;
        stream_ack <= 1'b0;
        done <= 1'b0;
        error <= 1'b0;
        busy <= 1'b0;
    end else begin
        done <= 1'b0;
        sha_valid <= 1'b0;
        hot_lookup_start <= 1'b0;
        hot_cfg_we <= 1'b0;
        hot_cfg_clear <= 1'b0;
        sha_digest_valid_d0 <= sha_digest_valid;
        stream_ack <= 1'b0;

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

                if (seq_id == CTRL_MAGIC) begin
                    if (payload_len >= 16'd5) begin
                        ram_read_addr <= 11'd4;
                        state <= ST_CTRL_OP_SETUP;
                    end else begin
                        digest <= 256'd0;
                        hot_hit <= 1'b0;
                        error <= 1'b1;
                        done <= 1'b1;
                        busy <= 1'b0;
                        state <= ST_IDLE;
                    end
                end else if (block_index_reg < full_blocks_reg) begin
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

            ST_CTRL_OP_SETUP: begin
                state <= ST_CTRL_OP_READ;
            end

            ST_CTRL_OP_READ: begin
                ctrl_op_reg <= ram_read_data;
                digest <= 256'd0;
                hot_hit <= 1'b0;

                if (ram_read_data == CTRL_CLEAR) begin
                    hot_cfg_clear <= 1'b1;
                    error <= 1'b0;
                    state <= ST_CTRL_DONE;
                end else if (ram_read_data == CTRL_WRITE_SLOT && payload_len >= 16'd39) begin
                    read_count_reg <= 7'd34;
                    read_index <= 7'd0;
                    ctrl_slot_reg <= 16'd0;
                    hot_cfg_digest <= 256'd0;
                    ram_read_addr <= 11'd5;
                    state <= ST_CTRL_DATA_SETUP;
                end else if (
                    (ram_read_data == CTRL_STREAM_START ||
                     ram_read_data == CTRL_STREAM_DATA ||
                     ram_read_data == CTRL_STREAM_END) &&
                    payload_len >= 16'd13
                ) begin
                    ctrl_op_reg <= ram_read_data;
                    ctrl_stream_id_reg <= 32'd0;
                    ctrl_stream_total_len_reg <= 32'd0;
                    read_count_reg <= 7'd8;
                    read_index <= 7'd0;
                    ram_read_addr <= 11'd5;
                    state <= ST_STREAM_HDR_SETUP;
                end else begin
                    error <= 1'b1;
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= ST_IDLE;
                end
            end

            ST_CTRL_DATA_SETUP: begin
                state <= ST_CTRL_DATA_READ;
            end

            ST_CTRL_DATA_READ: begin
                if (read_index == 7'd0)
                    ctrl_slot_reg[15:8] <= ram_read_data;
                else if (read_index == 7'd1)
                    ctrl_slot_reg[7:0] <= ram_read_data;
                else
                    hot_cfg_digest[255 - ((read_index - 7'd2) * 8) -: 8] <= ram_read_data;

                if (read_index + 1 < read_count_reg) begin
                    read_index <= read_index + 1'b1;
                    ram_read_addr <= ram_read_addr + 1'b1;
                    state <= ST_CTRL_DATA_SETUP;
                end else begin
                    state <= ST_CTRL_APPLY;
                end
            end

            ST_CTRL_APPLY: begin
                if (ctrl_slot_reg < 16'd512) begin
                    hot_cfg_slot <= ctrl_slot_reg[8:0];
                    hot_cfg_we <= 1'b1;
                    error <= 1'b0;
                end else begin
                    error <= 1'b1;
                end

                digest <= 256'd0;
                hot_hit <= 1'b0;
                state <= ST_CTRL_DONE;
            end

            ST_CTRL_DONE: begin
                done <= 1'b1;
                busy <= 1'b0;
                state <= ST_IDLE;
            end

            ST_STREAM_HDR_SETUP: begin
                state <= ST_STREAM_HDR_READ;
            end

            ST_STREAM_HDR_READ: begin
                case (read_index)
                    7'd0: ctrl_stream_id_reg[31:24] <= ram_read_data;
                    7'd1: ctrl_stream_id_reg[23:16] <= ram_read_data;
                    7'd2: ctrl_stream_id_reg[15:8]  <= ram_read_data;
                    7'd3: ctrl_stream_id_reg[7:0]   <= ram_read_data;
                    7'd4: ctrl_stream_total_len_reg[31:24] <= ram_read_data;
                    7'd5: ctrl_stream_total_len_reg[23:16] <= ram_read_data;
                    7'd6: ctrl_stream_total_len_reg[15:8]  <= ram_read_data;
                    default: ctrl_stream_total_len_reg[7:0] <= ram_read_data;
                endcase

                if (read_index + 1 < read_count_reg) begin
                    read_index <= read_index + 1'b1;
                    ram_read_addr <= ram_read_addr + 1'b1;
                    state <= ST_STREAM_HDR_SETUP;
                end else begin
                    stream_packet_data_len_reg <= payload_len - 16'd13;
                    stream_packet_read_idx_reg <= 16'd0;
                    ram_read_addr <= 11'd13;

                    if (ctrl_op_reg == CTRL_STREAM_START) begin
                        stream_active <= 1'b1;
                        stream_id_reg <= ctrl_stream_id_reg;
                        stream_total_len_reg <= {ctrl_stream_total_len_reg[31:8], ram_read_data};
                        stream_bytes_seen_reg <= 32'd0;
                        stream_partial_len_reg <= 6'd0;
                        stream_partial_block <= 512'd0;
                        stream_finalizing <= 1'b0;
                        stream_need_len_block <= 1'b0;
                        stream_final_second <= 1'b0;
                        digest <= 256'd0;
                        hot_hit <= 1'b0;
                        error <= 1'b0;
                        if (payload_len == 16'd13)
                            state <= ST_STREAM_FINISH_PACKET;
                        else
                            state <= ST_STREAM_DATA_SETUP;
                    end else if (stream_active && ctrl_stream_id_reg == stream_id_reg) begin
                        if (payload_len == 16'd13) begin
                            if (ctrl_op_reg == CTRL_STREAM_END)
                                state <= ST_STREAM_FINAL_PREP;
                            else
                                state <= ST_STREAM_FINISH_PACKET;
                        end else begin
                            state <= ST_STREAM_DATA_SETUP;
                        end
                    end else begin
                        error <= 1'b1;
                        done <= 1'b1;
                        busy <= 1'b0;
                        state <= ST_IDLE;
                    end
                end
            end

            ST_STREAM_DATA_SETUP: begin
                state <= ST_STREAM_DATA_READ;
            end

            ST_STREAM_DATA_READ: begin
                if (stream_bytes_seen_reg < stream_total_len_reg) begin
                    if (stream_partial_len_reg == 6'd63) begin
                        sha_block <= stream_partial_block;
                        sha_block[7:0] <= ram_read_data;
                        stream_partial_block <= 512'd0;
                        stream_partial_len_reg <= 6'd0;
                        stream_bytes_seen_reg <= stream_bytes_seen_reg + 1'b1;
                        stream_packet_read_idx_reg <= stream_packet_read_idx_reg + 1'b1;
                        if (stream_packet_read_idx_reg + 1 < stream_packet_data_len_reg)
                            ram_read_addr <= ram_read_addr + 1'b1;
                        stream_finalizing <= 1'b0;
                        state <= ST_STREAM_WAIT_READY;
                    end else begin
                        stream_partial_block[511 - (stream_partial_len_reg * 8) -: 8] <= ram_read_data;
                        stream_partial_len_reg <= stream_partial_len_reg + 1'b1;
                        stream_bytes_seen_reg <= stream_bytes_seen_reg + 1'b1;
                        stream_packet_read_idx_reg <= stream_packet_read_idx_reg + 1'b1;
                        if (stream_packet_read_idx_reg + 1 < stream_packet_data_len_reg) begin
                            ram_read_addr <= ram_read_addr + 1'b1;
                            state <= ST_STREAM_DATA_SETUP;
                        end else if (ctrl_op_reg == CTRL_STREAM_END) begin
                            state <= ST_STREAM_FINAL_PREP;
                        end else begin
                            state <= ST_STREAM_FINISH_PACKET;
                        end
                    end
                end else begin
                    error <= 1'b1;
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= ST_IDLE;
                end
            end

            ST_STREAM_WAIT_READY: begin
                if (sha_ready)
                    state <= ST_STREAM_SHA_START;
            end

            ST_STREAM_SHA_START: begin
                sha_valid <= 1'b1;
                sha_last <= stream_finalizing && !stream_need_len_block;
                state <= ST_STREAM_WAIT_BLOCK;
            end

            ST_STREAM_WAIT_BLOCK: begin
                if (sha_digest_valid && ~sha_digest_valid_d0) begin
                    if (stream_finalizing && !stream_need_len_block) begin
                        digest <= sha_digest;
                        stream_active <= 1'b0;
                        hot_lookup_start <= 1'b1;
                        state <= ST_HOT_LOOKUP_WAIT;
                    end else if (stream_finalizing && stream_need_len_block && !stream_final_second) begin
                        sha_block <= 512'd0;
                        sha_block[63:0] <= stream_bit_len;
                        stream_need_len_block <= 1'b0;
                        stream_final_second <= 1'b1;
                        state <= ST_STREAM_FINAL_WAIT;
                    end else if (stream_packet_read_idx_reg < stream_packet_data_len_reg) begin
                        state <= ST_STREAM_DATA_SETUP;
                    end else if (ctrl_op_reg == CTRL_STREAM_END) begin
                        state <= ST_STREAM_FINAL_PREP;
                    end else begin
                        state <= ST_STREAM_FINISH_PACKET;
                    end
                end
            end

            ST_STREAM_FINISH_PACKET: begin
                stream_ack <= 1'b1;
                digest <= 256'd0;
                hot_hit <= 1'b0;
                error <= 1'b0;
                done <= 1'b1;
                busy <= 1'b0;
                state <= ST_IDLE;
            end

            ST_STREAM_FINAL_PREP: begin
                if (stream_bytes_seen_reg == stream_total_len_reg) begin
                    sha_block <= stream_partial_block;
                    sha_block[511 - (stream_partial_len_reg * 8) -: 8] <= 8'h80;
                    stream_finalizing <= 1'b1;
                    stream_final_second <= 1'b0;
                    if (stream_partial_len_reg < 6'd56) begin
                        sha_block[63:0] <= stream_bit_len;
                        stream_need_len_block <= 1'b0;
                    end else begin
                        stream_need_len_block <= 1'b1;
                    end
                    state <= ST_STREAM_FINAL_WAIT;
                end else begin
                    error <= 1'b1;
                    done <= 1'b1;
                    busy <= 1'b0;
                    state <= ST_IDLE;
                end
            end

            ST_STREAM_FINAL_WAIT: begin
                if (sha_ready)
                    state <= ST_STREAM_FINAL_START;
            end

            ST_STREAM_FINAL_START: begin
                sha_valid <= 1'b1;
                sha_last <= !stream_need_len_block;
                state <= ST_STREAM_FINAL_BLOCK;
            end

            ST_STREAM_FINAL_BLOCK: begin
                if (sha_digest_valid && ~sha_digest_valid_d0) begin
                    if (stream_need_len_block && !stream_final_second) begin
                        sha_block <= 512'd0;
                        sha_block[63:0] <= stream_bit_len;
                        stream_need_len_block <= 1'b0;
                        stream_final_second <= 1'b1;
                        state <= ST_STREAM_FINAL_WAIT;
                    end else begin
                        digest <= sha_digest;
                        stream_active <= 1'b0;
                        hot_lookup_start <= 1'b1;
                        state <= ST_HOT_LOOKUP_WAIT;
                    end
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
