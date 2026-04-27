//////////////////////////////////////////////////////////////////////////////////////
//Module Name : mac_top
//Description :
//
//////////////////////////////////////////////////////////////////////////////////////
`timescale 1 ns/1 ns
module mac_test
(
 input                rst_n  ,
 input [31:0]         pack_total_len,
 input                gmii_tx_clk ,
 input                gmii_rx_clk ,
 input                gmii_rx_dv,
 input  [7:0]         gmii_rxd,
 output reg           gmii_tx_en,
 output reg [7:0]     gmii_txd
);

wire                 gmii_tx_en_tmp ;
wire   [7:0]         gmii_txd_tmp ;

wire                 udp_ram_data_req ;
reg   [15:0]         udp_send_data_length ;
reg   [7:0]          ram_wr_data ;
reg                  ram_wr_en ;
wire                 udp_tx_req ;
wire                 arp_request_req ;
wire                 mac_send_end ;
wire [7:0]           udp_rec_ram_rdata ;
wire [15:0]          udp_rec_data_length ;
wire                 udp_rec_data_valid ;
wire                 udp_tx_end ;
wire                 almost_full ;
wire                 mac_not_exist ;
wire                 arp_found ;

reg                  gmii_rx_dv_d0 ;
reg   [7:0]          gmii_rxd_d0 ;

reg                  reply_pending ;
reg   [255:0]        hash_digest_buf ;
reg                  hash_error_buf ;
reg   [5:0]          hash_write_cnt ;
reg                  almost_full_d0 ;
reg                  almost_full_d1 ;
reg                  digest_capture_pending ;
reg                  hash_done_toggle_tx_d0 ;
reg                  hash_done_toggle_tx_d1 ;

reg                  udp_rec_data_valid_d0_rx ;
reg                  hash_start_rx ;
reg   [15:0]         reply_payload_len_rx ;
reg   [255:0]        hash_digest_buf_rx ;
reg                  hash_error_buf_rx ;
reg                  hash_done_toggle_rx ;

wire [10:0]          sha_ram_read_addr ;
wire [255:0]         sha_digest ;
wire                 sha_done ;
wire                 sha_error ;
wire                 sha_busy ;
wire [10:0]          udp_rec_ram_read_addr ;

parameter IDLE          = 7'b000_0001 ;
parameter ARP_REQ       = 7'b000_0010 ;
parameter ARP_SEND      = 7'b000_0100 ;
parameter ARP_WAIT      = 7'b000_1000 ;
parameter CHECK_ARP     = 7'b001_0000 ;
parameter GEN_REQ       = 7'b010_0000 ;
parameter WRITE_RAM     = 7'b100_0000 ;

reg [6:0]    state  ;
reg [6:0]    next_state ;

wire write_ram_end;

always @(posedge gmii_tx_clk or negedge rst_n)
  begin
    if (~rst_n)
      state <= IDLE ;
    else
      state <= next_state ;
  end

always @(*)
  begin
    case(state)
      IDLE:
        begin
          if (reply_pending)
            next_state <= CHECK_ARP ;
          else
            next_state <= IDLE ;
        end

      ARP_REQ:
        next_state <= ARP_SEND ;

      ARP_SEND:
        begin
          if (mac_send_end)
            next_state <= ARP_WAIT ;
          else
            next_state <= ARP_SEND ;
        end

      ARP_WAIT:
        begin
          if (arp_found)
            next_state <= CHECK_ARP ;
          else
            next_state <= ARP_WAIT ;
        end

      CHECK_ARP:
        begin
          if (mac_not_exist)
            next_state <= ARP_REQ ;
          else if (almost_full_d1)
            next_state <= CHECK_ARP ;
          else
            next_state <= GEN_REQ ;
        end

      GEN_REQ:
        begin
          if (udp_ram_data_req)
            next_state <= WRITE_RAM ;
          else
            next_state <= GEN_REQ ;
        end

      WRITE_RAM:
        begin
          if (write_ram_end)
            next_state <= IDLE ;
          else
            next_state <= WRITE_RAM ;
        end

      default:
        next_state <= IDLE ;
    endcase
  end

always@(posedge gmii_rx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      begin
        gmii_rx_dv_d0 <= 1'b0 ;
        gmii_rxd_d0   <= 8'd0 ;
      end
    else
      begin
        gmii_rx_dv_d0 <= gmii_rx_dv ;
        gmii_rxd_d0   <= gmii_rxd ;
      end
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      begin
        gmii_tx_en <= 1'b0 ;
        gmii_txd   <= 8'd0 ;
      end
    else
      begin
        gmii_tx_en <= gmii_tx_en_tmp ;
        gmii_txd   <= gmii_txd_tmp ;
      end
  end

always@(posedge gmii_rx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      begin
        udp_rec_data_valid_d0_rx <= 1'b0 ;
        hash_start_rx            <= 1'b0 ;
        reply_payload_len_rx     <= 16'd0 ;
        hash_digest_buf_rx       <= 256'd0 ;
        hash_error_buf_rx        <= 1'b0 ;
        hash_done_toggle_rx      <= 1'b0 ;
      end
    else
      begin
        udp_rec_data_valid_d0_rx <= udp_rec_data_valid ;
        hash_start_rx <= 1'b0 ;

        if (udp_rec_data_valid && ~udp_rec_data_valid_d0_rx && ~sha_busy)
          begin
            reply_payload_len_rx <= udp_rec_data_length - 16'd8 ;
            hash_start_rx <= 1'b1 ;
          end

        if (sha_done)
          begin
            hash_digest_buf_rx  <= sha_digest ;
            hash_error_buf_rx   <= sha_error ;
            hash_done_toggle_rx <= ~hash_done_toggle_rx ;
          end
      end
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      begin
        reply_pending           <= 1'b0 ;
        hash_digest_buf         <= 256'd0 ;
        hash_error_buf          <= 1'b0 ;
        digest_capture_pending  <= 1'b0 ;
        hash_done_toggle_tx_d0  <= 1'b0 ;
        hash_done_toggle_tx_d1  <= 1'b0 ;
      end
    else
      begin
        hash_done_toggle_tx_d0 <= hash_done_toggle_rx ;
        hash_done_toggle_tx_d1 <= hash_done_toggle_tx_d0 ;

        if (state == WRITE_RAM && next_state == IDLE)
          begin
            reply_pending <= 1'b0 ;
          end

        if (hash_done_toggle_tx_d0 ^ hash_done_toggle_tx_d1)
          begin
            digest_capture_pending <= 1'b1 ;
          end
        else if (digest_capture_pending)
          begin
            hash_digest_buf        <= hash_digest_buf_rx ;
            hash_error_buf         <= hash_error_buf_rx ;
            reply_pending          <= 1'b1 ;
            digest_capture_pending <= 1'b0 ;
          end
      end
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      udp_send_data_length <= 16'd32 ;
    else
      udp_send_data_length <= 16'd32 ;
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      hash_write_cnt <= 6'd0 ;
    else if (state == WRITE_RAM)
      hash_write_cnt <= hash_write_cnt + 1'b1 ;
    else
      hash_write_cnt <= 6'd0 ;
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      ram_wr_en <= 1'b0 ;
    else if (state == WRITE_RAM && hash_write_cnt < 6'd32)
      ram_wr_en <= 1'b1 ;
    else
      ram_wr_en <= 1'b0 ;
  end

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      ram_wr_data <= 8'd0 ;
    else if (state == WRITE_RAM)
      begin
        if (hash_error_buf)
          ram_wr_data <= 8'd0 ;
        else
          case (hash_write_cnt)
            6'd0  : ram_wr_data <= hash_digest_buf[255:248] ;
            6'd1  : ram_wr_data <= hash_digest_buf[247:240] ;
            6'd2  : ram_wr_data <= hash_digest_buf[239:232] ;
            6'd3  : ram_wr_data <= hash_digest_buf[231:224] ;
            6'd4  : ram_wr_data <= hash_digest_buf[223:216] ;
            6'd5  : ram_wr_data <= hash_digest_buf[215:208] ;
            6'd6  : ram_wr_data <= hash_digest_buf[207:200] ;
            6'd7  : ram_wr_data <= hash_digest_buf[199:192] ;
            6'd8  : ram_wr_data <= hash_digest_buf[191:184] ;
            6'd9  : ram_wr_data <= hash_digest_buf[183:176] ;
            6'd10 : ram_wr_data <= hash_digest_buf[175:168] ;
            6'd11 : ram_wr_data <= hash_digest_buf[167:160] ;
            6'd12 : ram_wr_data <= hash_digest_buf[159:152] ;
            6'd13 : ram_wr_data <= hash_digest_buf[151:144] ;
            6'd14 : ram_wr_data <= hash_digest_buf[143:136] ;
            6'd15 : ram_wr_data <= hash_digest_buf[135:128] ;
            6'd16 : ram_wr_data <= hash_digest_buf[127:120] ;
            6'd17 : ram_wr_data <= hash_digest_buf[119:112] ;
            6'd18 : ram_wr_data <= hash_digest_buf[111:104] ;
            6'd19 : ram_wr_data <= hash_digest_buf[103:96] ;
            6'd20 : ram_wr_data <= hash_digest_buf[95:88] ;
            6'd21 : ram_wr_data <= hash_digest_buf[87:80] ;
            6'd22 : ram_wr_data <= hash_digest_buf[79:72] ;
            6'd23 : ram_wr_data <= hash_digest_buf[71:64] ;
            6'd24 : ram_wr_data <= hash_digest_buf[63:56] ;
            6'd25 : ram_wr_data <= hash_digest_buf[55:48] ;
            6'd26 : ram_wr_data <= hash_digest_buf[47:40] ;
            6'd27 : ram_wr_data <= hash_digest_buf[39:32] ;
            6'd28 : ram_wr_data <= hash_digest_buf[31:24] ;
            6'd29 : ram_wr_data <= hash_digest_buf[23:16] ;
            6'd30 : ram_wr_data <= hash_digest_buf[15:8] ;
            6'd31 : ram_wr_data <= hash_digest_buf[7:0] ;
            default : ram_wr_data <= 8'd0 ;
          endcase
      end
    else
      ram_wr_data <= 8'd0 ;
  end

assign write_ram_end = (state == WRITE_RAM && hash_write_cnt == 6'd32) ;

always@(posedge gmii_tx_clk or negedge rst_n)
  begin
    if(rst_n == 1'b0)
      begin
        almost_full_d0 <= 1'b0 ;
        almost_full_d1 <= 1'b0 ;
      end
    else
      begin
        almost_full_d0 <= almost_full ;
        almost_full_d1 <= almost_full_d0 ;
      end
  end

assign udp_rec_ram_read_addr = sha_ram_read_addr ;
assign udp_tx_req = (state == GEN_REQ) ;
assign arp_request_req = (state == ARP_REQ) ;

udp_sha256_oneblock sha256_oneblock_inst
(
 .clk            (gmii_rx_clk         ),
 .rst_n          (rst_n               ),
 .start          (hash_start_rx       ),
 .payload_len    (reply_payload_len_rx),
 .ram_read_addr  (sha_ram_read_addr   ),
 .ram_read_data  (udp_rec_ram_rdata   ),
 .digest         (sha_digest          ),
 .done           (sha_done            ),
 .error          (sha_error           ),
 .busy           (sha_busy            )
);

mac_top mac_top0
(
 .gmii_tx_clk                 (gmii_tx_clk)                  ,
 .gmii_rx_clk                 (gmii_rx_clk)                  ,
 .rst_n                       (rst_n)  ,

 .source_mac_addr             (48'h00_0a_35_01_fe_c0)   ,
 .TTL                         (8'h80),
 .source_ip_addr              (32'hc0a80002),
 .destination_ip_addr         (32'hc0a80003),
 .udp_send_source_port        (16'h1f90),
 .udp_send_destination_port   (16'h1f90),

 .ram_wr_data                 (ram_wr_data) ,
 .ram_wr_en                   (ram_wr_en),
 .udp_ram_data_req            (udp_ram_data_req),
 .udp_send_data_length        (udp_send_data_length),
 .udp_tx_end                  (udp_tx_end           ),
 .almost_full                 (almost_full          ),

 .udp_tx_req                  (udp_tx_req),
 .arp_request_req             (arp_request_req ),

 .mac_send_end                (mac_send_end),
 .mac_data_valid              (gmii_tx_en_tmp),
 .mac_tx_data                 (gmii_txd_tmp),
 .rx_dv                       (gmii_rx_dv_d0   ),
 .mac_rx_datain               (gmii_rxd_d0 ),

 .udp_rec_ram_rdata           (udp_rec_ram_rdata),
 .udp_rec_ram_read_addr       (udp_rec_ram_read_addr),
 .udp_rec_data_length         (udp_rec_data_length ),

 .udp_rec_data_valid          (udp_rec_data_valid),
 .arp_found                   (arp_found ),
 .mac_not_exist               (mac_not_exist )
) ;

endmodule
