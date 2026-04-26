
module util_gmii_to_rgmii (
  reset,
  rgmii_td,
  rgmii_tx_ctl,
  rgmii_txc,
  rgmii_rd,
  rgmii_rx_ctl,
  gmii_rx_clk,
  rgmii_rxc,
  gmii_txd,
  gmii_tx_en,
  gmii_tx_er,
  gmii_tx_clk,
  gmii_crs,
  gmii_col,
  gmii_rxd,
  gmii_rx_dv,
  gmii_rx_er,
  speed_selection,
  duplex_mode
  );
  input           rgmii_rxc;//add
  input           reset;
  output  [ 3:0]  rgmii_td;
  output          rgmii_tx_ctl;
  output          rgmii_txc;
  input   [ 3:0]  rgmii_rd;
  input           rgmii_rx_ctl;
  output           gmii_rx_clk;
  input   [ 7:0]  gmii_txd;
  input           gmii_tx_en;
  input           gmii_tx_er;
  output          gmii_tx_clk;
  output          gmii_crs;
  output          gmii_col;
  output  [ 7:0]  gmii_rxd;
  output          gmii_rx_dv;
  output          gmii_rx_er;
  input  [ 1:0]   speed_selection; // 1x gigabit, 01 100Mbps, 00 10mbps
  input           duplex_mode;     // 1 full, 0 half
  
  wire gigabit;
  wire gmii_tx_clk_s;
  wire gmii_rx_dv_s;

  wire  [ 7:0]    gmii_rxd_s;
  wire            rgmii_rx_ctl_delay;
  wire            rgmii_rx_ctl_s;
  // registers
  reg             tx_reset_d1;
  reg             tx_reset_sync;
  reg             rx_reset_d1;
  reg   [ 7:0]    gmii_txd_r;
  reg             gmii_tx_en_r;
  reg             gmii_tx_er_r;
  reg   [ 7:0]    gmii_txd_r_d1;
  reg             gmii_tx_en_r_d1;
  reg             gmii_tx_er_r_d1;

  reg             rgmii_tx_ctl_r;
  reg   [ 3:0]    gmii_txd_low;
  reg             gmii_col;
  reg             gmii_crs;

  reg  [ 7:0]     gmii_rxd;
  reg             gmii_rx_dv;
  reg             gmii_rx_er;
  wire            gmii_rx_clk_s;
  reg[1:0] speed_selection_d0;
  reg[1:0] speed_selection_d1;
  always @(posedge gmii_rx_clk)
  begin
      speed_selection_d0<= speed_selection;
      speed_selection_d1<= speed_selection_d0;
  end
  assign gigabit        = 1'b1;
  assign gmii_tx_clk    = gmii_tx_clk_s;
  assign gmii_tx_clk_s  = gmii_rx_clk;

   assign gmii_rx_clk=rgmii_rxc;
  always @(posedge gmii_rx_clk)
  begin
    gmii_rxd       = gmii_rxd_s;
    gmii_rx_dv     = gmii_rx_dv_s;
    gmii_rx_er     = gmii_rx_dv_s ^ rgmii_rx_ctl_s;
  end

  always @(posedge gmii_tx_clk_s) begin
    tx_reset_d1    <= reset;
    tx_reset_sync  <= tx_reset_d1;
  end

  always @(posedge gmii_tx_clk_s)
  begin
    rgmii_tx_ctl_r = gmii_tx_en_r ^ gmii_tx_er_r;
    gmii_txd_low   = gigabit ? gmii_txd_r[7:4] :  gmii_txd_r[3:0];
    gmii_col       = duplex_mode ? 1'b0 : (gmii_tx_en_r| gmii_tx_er_r) & ( gmii_rx_dv | gmii_rx_er) ;
    gmii_crs       = duplex_mode ? 1'b0 : (gmii_tx_en_r| gmii_tx_er_r| gmii_rx_dv | gmii_rx_er);
  end

  always @(posedge gmii_tx_clk_s) begin
    if (tx_reset_sync == 1'b1) begin
      gmii_txd_r   <= 8'h0;
      gmii_tx_en_r <= 1'b0;
      gmii_tx_er_r <= 1'b0;
    end
    else
    begin
      gmii_txd_r   <= gmii_txd;
      gmii_tx_en_r <= gmii_tx_en;
      gmii_tx_er_r <= gmii_tx_er;
      gmii_txd_r_d1   <= gmii_txd_r;
      gmii_tx_en_r_d1 <= gmii_tx_en_r;
      gmii_tx_er_r_d1 <= gmii_tx_er_r;
    end
  end




ODDRE1 #(
   .IS_C_INVERTED(1'b0),      // Optional inversion for C
   .IS_D1_INVERTED(1'b0),     // Unsupported, do not use
   .IS_D2_INVERTED(1'b0),     // Unsupported, do not use
   .SRVAL(1'b0)               // Initializes the ODDRE1 Flip-Flops to the specified value (1'b0, 1'b1)
)
rgmii_txc_out (
   .Q(rgmii_txc),   // 1-bit output: Data output to IOB
   .C(gmii_tx_clk_s),   // 1-bit input: High-speed clock input
   .D1(1), // 1-bit input: Parallel data input 1
   .D2(0), // 1-bit input: Parallel data input 2
   .SR(0)  // 1-bit input: Active High Async Reset
);

generate
genvar i;
for (i = 0; i < 4; i = i + 1) begin : gen_tx_data
ODDRE1 #(
   .IS_C_INVERTED(1'b0),      // Optional inversion for C
   .IS_D1_INVERTED(1'b0),     // Unsupported, do not use
   .IS_D2_INVERTED(1'b0),     // Unsupported, do not use
   .SRVAL(1'b0)               // Initializes the ODDRE1 Flip-Flops to the specified value (1'b0, 1'b1)
)
rgmii_td_out (
   .Q(rgmii_td[i]),   // 1-bit output: Data output to IOB
   .C(gmii_tx_clk_s),   // 1-bit input: High-speed clock input
   .D1(gmii_txd_r_d1[i]), // 1-bit input: Parallel data input 1
   .D2(gmii_txd_low[i]), // 1-bit input: Parallel data input 2
   .SR(0)  // 1-bit input: Active High Async Reset
);
end
endgenerate


ODDRE1 #(
   .IS_C_INVERTED(1'b0),      // Optional inversion for C
   .IS_D1_INVERTED(1'b0),     // Unsupported, do not use
   .IS_D2_INVERTED(1'b0),     // Unsupported, do not use
   .SRVAL(1'b0)               // Initializes the ODDRE1 Flip-Flops to the specified value (1'b0, 1'b1)
)
rgmii_tx_ctl_out (
   .Q(rgmii_tx_ctl),   // 1-bit output: Data output to IOB
   .C(gmii_tx_clk_s),   // 1-bit input: High-speed clock input
   .D1(gmii_tx_en_r_d1), // 1-bit input: Parallel data input 1
   .D2(rgmii_tx_ctl_r), // 1-bit input: Parallel data input 2
   .SR(0)  // 1-bit input: Active High Async Reset
);
 
  generate
  for (i = 0; i < 4; i = i + 1) begin

	  
   IDDRE1 #(
      .DDR_CLK_EDGE("SAME_EDGE_PIPELINED"), // IDDRE1 mode (OPPOSITE_EDGE, SAME_EDGE, SAME_EDGE_PIPELINED)
      .IS_CB_INVERTED(1'b1),          // Optional inversion for CB
      .IS_C_INVERTED(1'b0)            // Optional inversion for C
   )
   rgmii_rx_iddr (
      .Q1(gmii_rxd_s[i]), // 1-bit output: Registered parallel output 1
      .Q2(gmii_rxd_s[i+4]), // 1-bit output: Registered parallel output 2
      .C(gmii_rx_clk),   // 1-bit input: High-speed clock
      .CB(gmii_rx_clk), // 1-bit input: Inversion of High-speed clock C
      .D(rgmii_rd[i]),   // 1-bit input: Serial Data Input
      .R(0)    // 1-bit input: Active High Async Reset
   );
  end
  endgenerate

   IDDRE1 #(
      .DDR_CLK_EDGE("SAME_EDGE_PIPELINED"), // IDDRE1 mode (OPPOSITE_EDGE, SAME_EDGE, SAME_EDGE_PIPELINED)
      .IS_CB_INVERTED(1'b1),          // Optional inversion for CB
      .IS_C_INVERTED(1'b0)            // Optional inversion for C
   )
   rgmii_rx_ctl_iddr (
      .Q1(gmii_rx_dv_s), // 1-bit output: Registered parallel output 1
      .Q2(rgmii_rx_ctl_s), // 1-bit output: Registered parallel output 2
      .C(gmii_rx_clk),   // 1-bit input: High-speed clock
      .CB(gmii_rx_clk), // 1-bit input: Inversion of High-speed clock C
      .D(rgmii_rx_ctl),   // 1-bit input: Serial Data Input
      .R(0)    // 1-bit input: Active High Async Reset
   );

endmodule
