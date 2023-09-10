# Computer Networks Assignment 1

The following repository contains the solutions for the Assignment 1 of Computer Networks,
The Assignment can be found under the file name Assignment-1 in the repository.  

### Question 1: Execution steps

1. Open the terminal and navigate to the directory where the file is located.
2. Run the following command to compile the file:
    ```bash
    gcc problem1.c
    sudo ./a.out
    ```
    The code should be run in root mode as it requires the root privileges to create the raw socket.  
3. Open another terminal for tcp replay and run the following command:
    ```bash
    sudo tcpreplay -i lo --mbps=0.5 prob1.pcap
    ```
    The above command will replay the pcap file at 1Mbps speed. It is better to turn off internet to avoid the socket from receiving other packets.
4. The output of the program will be written in the file [logsq1.txt](logsq1.txt) in the same directory.

5. For the question of number of flows and their
4-tuple, when the program is terminated using Ctrl+C the terminal will output number of flows and their 4-tuples, the output can be large.

### Question 2: Execution steps

1. Open the terminal and navigate to the directory where the file is located.

