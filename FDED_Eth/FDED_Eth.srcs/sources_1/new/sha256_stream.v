//======================================================================
//
// sha256_stream.v
// ----------------
// Stream wrapper for sha256_core with explicit net types for Vivado
// projects using `default_nettype none`.
//
//======================================================================

module sha256_stream (
    input  wire         clk,
    input  wire         rst,
    input  wire         mode,
    input  wire [511:0] s_tdata_i,
    input  wire         s_tlast_i,
    input  wire         s_tvalid_i,
    output wire         s_tready_o,
    output wire [255:0] digest_o,
    output wire         digest_valid_o
);

reg first_block;

always @(posedge clk) begin
    if (rst) begin
        first_block <= 1'b1;
    end else if (s_tvalid_i && s_tready_o) begin
        first_block <= s_tlast_i;
    end
end

sha256_core core (
    .clk(clk),
    .reset_n(~rst),
    .init(s_tvalid_i && first_block),
    .next(s_tvalid_i && !first_block),
    .mode(mode),
    .block(s_tdata_i),
    .ready(s_tready_o),
    .digest(digest_o),
    .digest_valid(digest_valid_o)
);

endmodule
