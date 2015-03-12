# Linux Network Load Balancing

This is a port of original lnlb project from source forge to Git.

Linux Network Load Balancing is an open-source project (kernel module + userland app.) aimed to realize decentered network load balancing clusters between Linux boxes.

In a few words: a common IP shared between all nodes (on a virtual interface). All you have to do is to bind on the virtual interface, the driver will do the rest

Features:
 * Zero configuration needed. Just the IP address and the device to bind to (e.g. eth0)
 * Scalability: new nodes can be added in every moment without interrupting services and without editing any conf.
 * Fault tolerance: dead nodes are detected and removed from cluster within (approx.) 10 sec. (time is configurable) and their connections are redistributed among the remaining nodes.
 * Requires no additional machines that do the balance process. Just the node boxes themselves.
 * Layer 3 transparency: since it's not proxy based it's totally transparent at Layer 3 (IP) level. External hosts see the cluster as a unique host.


Original project URL: http://lnlb.sourceforge.net/index.html
