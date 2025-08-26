
# Perf Test App

A simple **bare-metal application**, written in C and using only the `hbldv` driver, to perform **ping-pong, bandwidth, and latency tests** on Gaudi's NICs only.  
This application is designed for **low-level, high-performance connectivity validation** of RDMA-capable devices.

### Key Characteristics
- Uses the **Reliable Connection (RC)** transport type exclusively.  
- Performs data transfers using the **`rdma_write`** operation only. 

### Prerequisites
Before running the application, ensure you have the following:
- RDMA core.
- Habanalabs driver.
- See more info on how to install the driver [link](https://docs.habana.ai/en/latest/Installation_Guide/Custom_Driver_and_Software_Installation.html#custom-driver-and-software-installation)

### Environment
The app supports Gaudi 3 and Gaudi 2. Stand-alone (SA) devices or HLS.
- **Setup Connection**: You can connect device to device directly or connect two HLS/SA through a switch (switch needs to support RDMA RoCE)
- **Setup Configuration**:
    - If you are using a switch to connect the devices. You need to ensure you have ***ipv4*** configured and in the app, use the ```-g {idx}``` flag, which __idx__ refers to the gid index table of ```RoCE v2``` type.
    - How to find the correct __idx__?
        - Navigate to the gid attributes folder and search for the __idx__ that has ```RoCE V2``` type.
        - ``` cd /sys/class/infiniband/{dev_name}/ports/{port_number}/gid_attrs/types/```
        - run ```cat``` on all the __idx__ files to see what type each __idx__ is. 
    - if you are connecting device to device directly, _no need_ for ***ipv4*** and use ``` -g 0 ``` flag.

## Building the Application
To compile the application, run the following command:
```
cmake .
make
```

## Usage 
You need to run the app on both sides, client and server. 
```
  ./perf_test [Opts]           start a server and wait for connection
  ./perf_test [Opts] <host>    connect to server at <host>

Options:
  -p, --port=<port>         listen on/connect to port <port> (default 18515)
  -d, --ib-dev=<dev>        use IB device <dev> (default first device found)
  -i, --ib-port=<port>      use port <port> of IB device (default 1)
  -s, --size=<size>         size of message to exchange (default 4096)
  -m, --mtu=<size>          path MTU (default 8192)
  -r, --rx-depth=<dep>      number of receives to post at a time (default 128)
  -n, --iters=<iters>       number of exchanges (default 1000)
  -l, --sl=<sl>             service level value (default 0)
  -g, --gid-idx=<gid index> local port gid index (default 2)
  -c, --chk                 validate received buffer
  -x, --logs                print additional log information
  -t, --test-type           'pp' = Ping-Pong Test <default>
                            'bw' = Bandwidth Test
                            'lt' = Latency Test
  -h, --help            help

```
