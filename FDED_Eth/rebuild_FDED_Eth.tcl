set origin_dir [file normalize [file dirname [info script]]]
set project_name FDED_Eth
set project_dir $origin_dir
set project_file [file join $project_dir "${project_name}.xpr"]

create_project -force $project_name $project_dir -part xcku040-ffva1156-2-i

set_property default_lib xil_defaultlib [current_project]
set_property target_language Verilog [current_project]

set rtl_files [list \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac arp_cache.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac rx arp_rx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx arp_tx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac crc.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src ethernet_test.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src arbi gmii_arbi.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src arbi gmii_rx_buffer.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src arbi gmii_tx_buffer.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac icmp_reply.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac hot_digest_table.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac rx ip_rx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx ip_tx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx ip_tx_mode.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac rx mac_rx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac rx mac_rx_top.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac mac_test.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac mac_top.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx mac_tx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx mac_tx_mode.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx mac_tx_top.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mdio smi_config.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mdio smi_read_write.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac rx udp_rx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src mac tx udp_tx.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new eth_src util_gmii_to_rgmii.v] \
  [file join $origin_dir FDED_Eth.srcs sources_1 new top.v] \
]

set ip_files [list \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip udp_rx_ram_8_2048 udp_rx_ram_8_2048.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip clk_wiz_0 clk_wiz_0.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip len_fifo len_fifo.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip udp_tx_data_fifo udp_tx_data_fifo.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip udp_checksum_fifo udp_checksum_fifo.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip eth_data_fifo eth_data_fifo.xci] \
  [file join $origin_dir FDED_Eth.srcs sources_1 ip icmp_rx_ram_8_256 icmp_rx_ram_8_256.xci] \
]

set constr_file [file join $origin_dir FDED_Eth.srcs constrs_1 new eth.xdc]

add_files -norecurse $rtl_files
add_files -fileset constrs_1 -norecurse $constr_file
add_files -norecurse $ip_files

set_property top top [get_filesets sources_1]
set_property top top [get_filesets sim_1]
set_property source_mgmt_mode DisplayOnly [current_project]
update_compile_order -fileset sources_1

if {[llength [get_ips -quiet]] > 0} {
  generate_target all [get_ips]
}

save_project

puts "Project created: $project_file"
puts "Open with: vivado $project_file"
