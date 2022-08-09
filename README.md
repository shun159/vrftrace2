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
  99% |█████████████████████████████████████████████████████ | (1563/1577, 89 it/s) [14s:0s]
Timestamp            CPU                         Function
506720751062727      003                         netif_rx
506720751088314      003                netif_rx_internal
506720751093939      003               enqueue_to_backlog
506720751104833      003              __netif_receive_skb
506720751113824      003     __netif_receive_skb_one_core
506720751121923      003                         skb_push
506720751126768      003                            vm_rx
506720751131103      003                     lh_pfrag_len
506720751135003      003                 vr_virtual_input
506720751138282      003                      vr_pkt_type
506720751141703      003                  vr_flow_forward
506720751144798      003              vr_inet_flow_lookup
506720751148405      003                vr_inet_form_flow
506720751152180      003          vr_flow_fat_flow_lookup
506720751155796      003             vr_inet_flow_nexthop
506720751158957      003                   vr_flow_lookup
506720751164065      003                     lh_pfrag_len
506720751166971      003                     lh_pfrag_len
506720751171021      003                   vr_flow_action
506720751175133      003           vr_flow_action_default
506720751178752      003                __vr_flow_forward
506720751181673      003                  vr_bridge_input
506720751184947      003          vr_ip_well_known_packet
506720751192194      003       lh_pkt_from_vm_tcp_mss_adj
506720751195575      003                        nh_output
506720751198835      003                      nh_encap_l2
506720751203548      003                           eth_tx
506720751206578      003             vif_plug_mac_request
506720751208925      003                     lh_pfrag_len
506720751212223      003                      linux_if_tx
506720751214421      003                     lh_pfrag_len
506720751218616      003               linux_xmit_segment
506720751222137      003                       linux_xmit
506720751225420      003                   dev_queue_xmit
506720751228773      003                 __dev_queue_xmit
506720751231732      003              netdev_core_pick_tx
506720751234929      003                validate_xmit_skb
506720751237786      003               netif_skb_features
506720751240482      003          passthru_features_check
506720751243076      003             skb_network_protocol
506720751246164      003               validate_xmit_xfrm
506720751249365      003              dev_hard_start_xmit
506720751252811      003           skb_clone_tx_timestamp
506720751255458      003                __dev_forward_skb
506720751257991      003               __dev_forward_skb2
506720751260565      003                 skb_scrub_packet
506720751263347      003                   eth_type_trans
^C2022/08/08 18:52:48 Tearing down perf buffer...
```

<!--
 Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
-->

