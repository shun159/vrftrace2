vrftrace2 (wip)
===
vrftrace2 is an eBPF-based tool for tracing function in the vrouter.ko.
It provides introspection of vrouter kernel module.

## Requirements
- Linux version: v4.17 or above
- Kernel Config
    - CONFIG_DEBUG_INFO_BTF
    - CONFIG_KPROBE
    - CONFIG_PERF_EVENTS
    - CONFIG_BPF
    - CONFIG_BPF_SYSCALL

## Build

```shellsession
$ make bin/vrft
```

## Basic usage

```shellsession
NAME:
   vrftrace - A new cli application

USAGE:
   vrft [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --kernel-btf value   Linux kernel BTF file (default: "/sys/kernel/btf/vmlinux")
   --vrouter-btf value  tf-vrouter.ko BTF file (default: "/tmp/vrouter.btf")
   --help, -h           show help
   --version, -v        print the version
```

## Sample output
```
2022/08/08 18:52:25 Dist Info(name = Arch Linux version = rolling)
2022/08/08 18:52:25 Kernel(release = 5.16.16-arch1-1)
2022/08/08 18:52:25 DEBUG_INFO_BTF is enabled
2022/08/08 18:52:26 Filter events with 4 interfaces on vrouter kernel...
2022/08/18 00:31:29 Filter events with 4 interfaces on vrouter kernel...
 100% |█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| (1577/1577, 106 it/s)
Timestamp            CPU                         Function
176370718136562      004 netif_rx() {                                                    
176370718164267      004   netif_rx_internal() {                                         
176370718174405      004     enqueue_to_backlog() {                                      
176370718178924      004     }                                                           
176370718182794      004   }                                                             
176370718185944      004 }                                                               
176370718201029      004 __netif_receive_skb() {                                         
176370718212586      004   __netif_receive_skb_one_core() {                              
176370718219862      004     skb_push() {                                                
176370718223355      004     }                                                           
176370718229461      004     vm_rx() {                                                   
176370718235710      004       lh_pfrag_len() {                                          
176370718240283      004       }                                                         
176370718246876      004       vr_virtual_input() {                                      
176370718251883      004         vr_pkt_type() {                                         
176370718255785      004         }                                                       
176370718260956      004         vr_flow_forward() {                                     
176370718265584      004           vr_inet_flow_lookup() {                               
176370718270103      004             vr_inet_form_flow() {                               
176370718274930      004               vr_flow_fat_flow_lookup() {                       
176370718279904      004               }                                                 
176370718285175      004               vr_inet_flow_nexthop() {                          
176370718288918      004               }                                                 
176370718293438      004             }                                                   
176370718297455      004             vr_flow_lookup() {                                  
176370718303022      004               lh_pfrag_len() {                                  
176370718305704      004               }                                                 
176370718308785      004               lh_pfrag_len() {                                  
176370718311411      004               }                                                 
176370718316302      004               vr_flow_action() {                                
176370718321251      004                 vr_flow_action_default() {                      
176370718325361      004                 }                                               
176370718328789      004               }                                                 
176370718332002      004             }                                                   
176370718335637      004           }                                                     
176370718340492      004           __vr_flow_forward() {                                 
176370718343854      004           }                                                     
176370718347283      004         }                                                       
176370718351124      004         vr_bridge_input() {                                     
176370718355392      004           vr_ip_well_known_packet() {                           
176370718359480      004           }                                                     
176370718365213      004           lh_pkt_from_vm_tcp_mss_adj() {                        
176370718368361      004           }                                                     
176370718375722      004           nh_output() {                                         
176370718383676      004             nh_encap_l2() {                                     
176370718389086      004               eth_tx() {                                        
176370718392948      004                 vif_plug_mac_request() {                        
176370718396867      004                 }                                               
176370718401159      004                 lh_pfrag_len() {                                
176370718404468      004                 }                                               
176370718411176      004                 linux_if_tx() {                                 
176370718414729      004                   lh_pfrag_len() {                              
176370718417788      004                   }                                             
176370718426394      004                   linux_xmit_segment() {                        
176370718431754      004                     linux_xmit() {                              
176370718437546      004                       dev_queue_xmit() {                        
176370718443192      004                         __dev_queue_xmit() {                    
176370718448572      004                           netdev_core_pick_tx() {               
176370718456222      004                           }                                     
176370718460656      004                           validate_xmit_skb() {                 
176370718464789      004                             netif_skb_features() {              
176370718469116      004                               passthru_features_check() {       
176370718472524      004                               }                                 
176370718476783      004                               skb_network_protocol() {          
176370718482832      004                               }                                 
176370718485591      004                             }                                   
176370718488994      004                             validate_xmit_xfrm() {              
176370718491784      004                             }                                   
176370718494338      004                           }                                     
176370718499347      004                           dev_hard_start_xmit() {               
176370718503844      004                             skb_clone_tx_timestamp() {          
176370718506667      004                             }                                   
176370718510600      004                             __dev_forward_skb() {               
176370718514161      004                               __dev_forward_skb2() {            
176370718518045      004                                 skb_scrub_packet() {            
176370718521393      004                                 }                               
176370718524946      004                                 eth_type_trans() {              
176370718528855      004                                 }                               
176370718532077      004                               }                                 
176370718535227      004                             }                                   
176370718543339      004                           }                                     
176370718549786      004                         }                                       
176370718553118      004                       }                                         
176370718556855      004                     }                                           
176370718561040      004                   }                                             
176370718564604      004                 }                                               
176370718568857      004               }                                                 
176370718572789      004             }                                                   
176370718577707      004           }                                                     
176370718582124      004         }                                                       
176370718586295      004       }                                                         
176370718590631      004     }                                                           
176370718595988      004   }                                                             
176370718599664      004 }                                                               

```

<!--
 Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
-->

