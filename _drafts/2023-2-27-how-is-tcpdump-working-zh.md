---
layout: post
title: Tcpump Deep Dive - How it is workin in kernel 
data: 2022-10-30
categories: 
- Linux
- Network
- Cilium
---

* TOC
{:toc}

# Background
While using Cilium, we have observed that in some cases, despite successful pinging, tcpdump fails to capture any packets. This article aims to delve into the mechanics of tcpdump in the kernel to shed light on this issue.

# Network processing by kernel 内核对网络数据的处理
在分析tcpdump的工作原理前，需要了解kernel对网络数据的处理过程。
Before dive deep, we need to understand how kernel processes data from network

<div style="text-align: center">
<img src="https://raw.githubusercontent.com/chnhaoran/chnhaoran.github.io/main/images/2022-10-30-tcpdump/overview.png"/>
</div>

Basically, when a network interface card (NIC) receives data frames from the wire
- It utilizes direct memory access (DMA) to write the data frame into a pre-allocated ring buffer.
- This triggers a hard interrupt to notify the CPU that there is network data to receive.
- Upon receiving the interrupt, the CPU triggers a soft interrupt
- It calls the driver's registered poll function to poll the data frames from the ring buffer.
- The data frames enter the network subsystem, where they pass through sub-systems such as tc, netfilter, and route for processing of L2/L3/L4 protocols.
- Finally, the data frames are sent to the corresponding user space registered sockets.


## Initialization
The kernel needs to complete the initialization to support the subsequent packet processing, including:

- Driver initialization
- Soft interrupt thread initialization
- Initialization of network stack processing functions


I will elaborate on driver initialization and soft interrupt thread initialization in further articles. This article only focuses on initialization of network stack processing functions.

Take IP as an example, the initialization processes of IPv4 and IPv6 are as follow.

```c++
// af_inet.c
static int __init inet_init(void)
{
    ...
    dev_add_pack(&ip_packet_type);
}

static struct packet_type ip_packet_type __read_mostly = {
	// Register ETH_P_IP & ip_rcv for IPv4
    .type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,
	.list_func = ip_list_rcv,
};


// af_inet6.c
static struct packet_type ipv6_packet_type __read_mostly = {
    // Register ETH_P_IPV6 & ip_rcv for IPv6
	.type = cpu_to_be16(ETH_P_IPV6),
	.func = ipv6_rcv,
	.list_func = ipv6_list_rcv,
};

static int __init ipv6_packet_init(void)
{
	dev_add_pack(&ipv6_packet_type);
	return 0;
}
```

In function `dev_add_pack`, protocols and corresponding handlers are added to ptype_all(ETH_P_ALL) or ptype_base (other protocols).

```c++
// dev.c
void dev_add_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);

	spin_lock(&ptype_lock);
	list_add_rcu(&pt->list, head);
	spin_unlock(&ptype_lock);
}

static inline struct list_head *ptype_head(const struct packet_type *pt)
{
	if (pt->type == htons(ETH_P_ALL))
		return pt->dev ? &pt->dev->ptype_all : &ptype_all;
	else
		return pt->dev ? &pt->dev->ptype_specific :
				 &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];
}

// if_ether.h
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
```

## RX side processing
在接收侧，`__netif_receive_skb_core`先判断`ptype_all`中是否有sniffer注册了`ETH_P_ALL`类型的协议，如果有，则送到对应的handler处理。再根据数据包的类型，将skb送给注册协议的handler，比如`ETH_P_IP`等。

```c++
//dev.c
static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc,
				    struct packet_type **ppt_prev)
{
    ...
    // XDP processing
    // ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);
    // deliver skb to ptype_all
    list_for_each_entry_rcu(ptype, &ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }

    list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    // tc handling
    // skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev, &another);
    ...
    // deliver skb to ptype_base
    if (likely(!deliver_exact)) {
		deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type, &ptype_base[ntohs(type) & PTYPE_HASH_MASK]);
	}

}
```
查看libpcap的代码，可以看到pcap使用的正是`ETH_P_ALL`协议，并注册了AF_PACKET类型的socket。

```c++
//libpcap-linux.c
static int pcap_protocol(pcap_t *handle)
{
	int protocol;

	protocol = handle->opt.protocol;
	if (protocol == 0)
		protocol = ETH_P_ALL;

	return htons(protocol);
}

static int iface_bind(int fd, int ifindex, char *ebuf, int protocol)
{
    ...
    sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex < 0 ? 0 : ifindex;
	sll.sll_protocol	= protocol;
    ...
}
```

在kernel中，注册socket会对应的增加一个proto的处理，对应的skb会发送给该协议相关的所有socket。这也就是为什么tcpdump可以在用户态收到网卡抓到包的原因。

```c++
// af_packet.c
static void __register_prot_hook(struct sock *sk)
{
	struct packet_sock *po = pkt_sk(sk);

	if (!po->running) {
		if (po->fanout)
			__fanout_link(sk, po);
		else
			dev_add_pack(&po->prot_hook);

		sock_hold(sk);
		po->running = 1;
	}
}

static void register_prot_hook(struct sock *sk)
{
	lockdep_assert_held_once(&pkt_sk(sk)->bind_lock);
	__register_prot_hook(sk);
}
```

## 发送端处理
接收端的方式也是一样的。协议栈处理完后，`__dev_queue_xmit`做最后的发送，先经过tc处理，再经过`ETH_P_ALL`协议的处理，发送给对应的处理函数。
```c++
// dev.c
static int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
{
    ...
    // tc processing
    //skb = sch_handle_egress(skb, &rc, dev);
    skb = dev_hard_start_xmit(skb, dev, txq, &rc);
}
```
```
dev_hard_start_xmit
   | dev_queue_xmit_nit
      | xmit_one
         | dev_queue_xmit_nit
```
```c++
void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
    list_for_each_entry_rcu(ptype, ptype_list, list) {
        ...
        if (pt_prev) {
            deliver_skb(skb2, pt_prev, skb->dev);
            pt_prev = ptype;
            continue;
        }
    }
}
```



