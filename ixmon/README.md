# IXmon

### Simplified overview
IXmon is a tool for network traffic analysis and aggregation. Given a stream
of NetFlows, IXmon aggregates traffic by time, srcAS, and dstAS. For instance,
IXmon aggregates all traffic from a given srcAS `S` to a dstAS `D` that was
observed in the past minute (the time interval can be configured).

### More details
In reality, IXmon also keeps track of transport-layer protocols and src/dst
ports. Also, it keeps track of traffic to/from of /24 subnets within a 
configurable set of AS numbers of interest.

### Installing dependencies
First, see the README file under `ixmon/dependencies` for pre-requisite 
packages. Then run `install_ixmon_dependencies.pl`
All needed dependencies, except for `bgpstream`, should be automatically installed. According to our
tests, this should work well on modern Ubuntu and Debian Linux distributions
(e.g., Ubuntu server 16.04 or Debian jessie). 

Make sure CAIDA's `bgpstream` is installed (it should be installed by our installation script), and that `libbgpstream.so.2` is in your `LD_LIBRARY_PATH` (see also https://bgpstream.caida.org/docs/install/bgpstream)

### Boost

You might also need to separately install Boost:
First download `boost_1_58_0.tar.gz` and unzip it in `/opt/`, then
```
cd /opt/boost_1_58_0/
./bootstrap.sh
./b2 -j4 --build-dir=/tmp/boost_build_temp_directory_1_5_8 link=shared --without-test --without-python --without-wave --without-graph --without-coroutine --without-math --without-log --without-graph_parallel --without-mpi
```

### Compiling IXmon
```
$ cd src
$ cmake ./
$ make
```

### Configuration
Copy `ixmon.conf.template` to `ixmon.conf` and make changes to the configuration
parameters to fit your environment.

### Running IXmon
To run IXmon, simply run
```
$ ./ixmon
```

### IXmon output
The output will be a set of export files (two per export time window) written
into the directory specified in `ixmon_expfile_template` (see `ixmon.conf`).
Each file contains traffic statistics exported in JSON format.

### Testing whether NetFlows are being received correctly

IXmon needs to receive NetFlows via UDP. The UDP port(s) on which flows are received is configurable (see `ixmon.conf`). To test if flows are being correctly received, you can run two simple tests. Assuming the interface in which flows are received is `eth0`, the IP address is `192.168.10.10` and the UDP port is `2055`:

```
sudo tshark -i eth0 -f "udp port 2055" -T fields \
       -e frame.number -e cflow.octets -e cflow.packets \
       -e cflow.inputint -e cflow.outputint -e cflow.srcaddr \
       -e cflow.dstaddr -e cflow.protocol -e cflow.tos \
       -e cflow.srcport -e cflow.dstport -e cflow.sampler_id \
       -e cflow.flow_class -e cflow.nexthop -e cflow.dstmask \
       -e cflow.srcmask -e cflow.tcpflags -e cflow.direction \
       -E header=y -E separator=, -E quote=d \
       -E occurrence=a -E aggregator=/s
```
and
```
nc -l -u 192.168.10.10 205
```
Tshark will print the NetFlows in a comma-separated format, whereas `nc` should print the UDP payload bytes on stdout for every newly received NetFlow packet.



