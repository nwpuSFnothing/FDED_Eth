`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2019/12/19 16:51:53
// Design Name: 
// Module Name: ethernet_top
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module top
	(
		input          		sys_clk_p, 
		input          		sys_clk_n, 
	
		input          		rst_n,
				
		output         		e_mdc,
		inout          		e_mdio,
		output		reg		e_reset,
				
		output [3:0]   		rgmii_txd,
		output         		rgmii_txctl,
		output         		rgmii_txc,
		input  [3:0]   		rgmii_rxd,
		input          		rgmii_rxctl,
		input          		rgmii_rxc


    );


wire sys_clk;
wire locked ;
reg  [4:0]rst_delay;

//assign e_reset = 1'b1 ;

clk_wiz_0 pll_inst
   (
    // Clock out ports
    .clk_out1(sys_clk),     // output clk_out1
    .reset(~rst_n), // input reset
    // Status and control signals
    .locked(locked),       // output locked
   // Clock in ports
    .clk_in1_p(sys_clk_p),    // input clk_in1_p
    .clk_in1_n(sys_clk_n));    // input clk_in1_n


always@(posedge sys_clk)begin
  if(!rst_n)
    rst_delay<=5'd0;
  else 
    rst_delay<=rst_delay+5'd1;
end

always@(posedge sys_clk)begin
  if(!rst_n)
    e_reset<= 1'd0;
  else if(rst_delay==5'd19) 
    e_reset<= 1'd1;
  else
    e_reset<= e_reset;
end

// ethernet_test#
// (
//	 .MAC_ADDR (48'h00_0a_35_01_fe_c2),
//	 .IP_ADDR  (32'hc0a80007)
// )
ethernet_test eth1
 (
  .rst_n         (locked      ),
  .sys_clk 	     (sys_clk 	  ),
  .led 	     ( 	  ),
  .e_mdc         (e_mdc      ),
  .e_mdio        (e_mdio     ),
  .rgmii_txd     (rgmii_txd  ),
  .rgmii_txctl   (rgmii_txctl),
  .rgmii_txc     (rgmii_txc  ),
  .rgmii_rxd     (rgmii_rxd  ),
  .rgmii_rxctl   (rgmii_rxctl),
  .rgmii_rxc     (rgmii_rxc  )
 
 );

	
endmodule
