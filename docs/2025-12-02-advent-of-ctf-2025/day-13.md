# Day 13

Follow the Cisco documentation and do the configurations step by step.

HQ-Router:

```
!
version 15.4
no service timestamps log datetime msec
no service timestamps debug datetime msec
no service password-encryption
!
hostname HQ-Router
!
!
!
enable secret 5 $1$mERr$658/YAajL6gFOtVVZQj.m/
!
!
!
!
!
!
ip cef
no ipv6 cef
!
!
!
username NetOps secret 5 $1$mERr$MU22bEUcBmKoHRzjcCWp30
!
!
!
!
!
!
!
!
!
!
ip ssh version 2
ip domain-name nexus.corp
!
!
spanning-tree mode pvst
!
!
!
!
!
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.1 255.255.255.252
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 Cisc0Rout3s
 duplex auto
 speed auto
!
interface GigabitEthernet0/0/1
 no ip address
 ip access-group SECURE_HQ out
 duplex auto
 speed auto
!
interface Vlan1
 no ip address
 shutdown
!
router ospf 1
 log-adjacency-changes
 area 0 authentication message-digest
 passive-interface GigabitEthernet0/0/1
 network 10.0.0.0 0.0.0.3 area 0
!
ip classless
!
ip flow-export version 9
!
!
ip access-list extended SECURE_HQ
 permit icmp 192.168.100.0 0.0.0.63 host 172.16.10.10
 permit tcp 192.168.100.0 0.0.0.63 host 172.16.10.10 eq www
 deny ip 192.168.100.64 0.0.0.63 host 172.16.10.10
!
!
!
!
!
line con 0
!
line aux 0
!
line vty 0 4
 login local
 transport input ssh
!
!
!
end
```

ISP-Router:

```
!
version 15.4
no service timestamps log datetime msec
no service timestamps debug datetime msec
no service password-encryption
!
hostname ISP-Router
!
!
!
enable secret 5 $1$mERr$658/YAajL6gFOtVVZQj.m/
!
!
!
!
!
!
ip cef
no ipv6 cef
!
!
!
username NetOps secret 5 $1$mERr$MU22bEUcBmKoHRzjcCWp30
!
!
!
!
!
!
!
!
!
!
ip ssh version 2
ip domain-name nexus.corp
!
!
spanning-tree mode pvst
!
!
!
!
!
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.2 255.255.255.252
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 Cisc0Rout3s
 duplex auto
 speed auto
!
interface GigabitEthernet0/0/1
 ip address 10.0.0.6 255.255.255.252
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 Cisc0Rout3s
 duplex auto
 speed auto
!
interface Vlan1
 no ip address
 shutdown
!
router ospf 1
 log-adjacency-changes
 area 0 authentication message-digest
 network 10.0.0.0 0.0.0.3 area 0
 network 10.0.0.4 0.0.0.3 area 0
!
ip classless
!
ip flow-export version 9
!
!
!
!
!
!
!
line con 0
!
line aux 0
!
line vty 0 4
 login local
 transport input ssh
!
!
!
end
```

Branch-Router:

```
!
version 15.4
no service timestamps log datetime msec
no service timestamps debug datetime msec
no service password-encryption
!
hostname Branch-Router
!
!
!
enable secret 5 $1$mERr$658/YAajL6gFOtVVZQj.m/
!
!
!
!
!
!
ip cef
no ipv6 cef
!
!
!
username NetOps secret 5 $1$mERr$MU22bEUcBmKoHRzjcCWp30
!
!
!
!
!
!
!
!
!
!
ip ssh version 2
ip domain-name nexus.corp
!
!
spanning-tree mode pvst
!
!
!
!
!
!
interface GigabitEthernet0/0/0
 ip address 10.0.0.5 255.255.255.252
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 Cisc0Rout3s
 duplex auto
 speed auto
!
interface GigabitEthernet0/0/1
 no ip address
 duplex auto
 speed auto
!
interface GigabitEthernet0/0/1.10
 encapsulation dot1Q 10
 ip address 192.168.100.1 255.255.255.192
!
interface GigabitEthernet0/0/1.20
 encapsulation dot1Q 20
 ip address 192.168.100.65 255.255.255.192
!
interface Vlan1
 no ip address
 shutdown
!
router ospf 1
 log-adjacency-changes
 area 0 authentication message-digest
 redistribute connected subnets 
 passive-interface GigabitEthernet0/0/1
 network 10.0.0.4 0.0.0.3 area 0
 network 192.168.100.0 0.0.0.255 area 0
!
router rip
!
ip classless
!
ip flow-export version 9
!
!
!
!
!
!
!
line con 0
!
line aux 0
!
line vty 0 4
 login local
 transport input ssh
!
!
!
end
```

Branch-Switch:

```
!
version 15.0
no service timestamps log datetime msec
no service timestamps debug datetime msec
no service password-encryption
!
hostname Switch
!
!
!
!
!
!
spanning-tree mode pvst
spanning-tree extend system-id
!
interface FastEthernet0/1
 switchport mode trunk
 switchport nonegotiate
!
interface FastEthernet0/2
 switchport access vlan 10
 switchport mode access
 switchport port-security
 switchport port-security mac-address sticky 
 switchport port-security violation restrict 
 switchport port-security mac-address sticky 0001.971B.A6CC
!
interface FastEthernet0/3
 switchport access vlan 20
 switchport mode access
 switchport port-security
 switchport port-security mac-address sticky 
 switchport port-security violation restrict 
 switchport port-security mac-address sticky 0001.9618.5835
!
interface FastEthernet0/4
 shutdown
!
interface FastEthernet0/5
 shutdown
!
interface FastEthernet0/6
 shutdown
!
interface FastEthernet0/7
 shutdown
!
interface FastEthernet0/8
 shutdown
!
interface FastEthernet0/9
 shutdown
!
interface FastEthernet0/10
 shutdown
!
interface FastEthernet0/11
 shutdown
!
interface FastEthernet0/12
 shutdown
!
interface FastEthernet0/13
 shutdown
!
interface FastEthernet0/14
 shutdown
!
interface FastEthernet0/15
 shutdown
!
interface FastEthernet0/16
 shutdown
!
interface FastEthernet0/17
 shutdown
!
interface FastEthernet0/18
 shutdown
!
interface FastEthernet0/19
 shutdown
!
interface FastEthernet0/20
 shutdown
!
interface FastEthernet0/21
 shutdown
!
interface FastEthernet0/22
 shutdown
!
interface FastEthernet0/23
 shutdown
!
interface FastEthernet0/24
 shutdown
!
interface GigabitEthernet0/1
!
interface GigabitEthernet0/2
!
interface Vlan1
 no ip address
 shutdown
!
interface Vlan10
 no ip address
!
interface Vlan20
 no ip address
!
!
!
!
line con 0
!
line vty 0 4
 login
line vty 5 15
 login
!
!
!
!
end
```

Result:

```
Your Score: 27 / 31

Congratulations! Here is your flag:

csd{C1sc0_35_muy_m4l_e290bgk7o5}
```
