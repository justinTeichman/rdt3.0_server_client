MUST:  Mike's UDP Simulator Tool

Usage: must [options]

Options:
 -f port   Forward incoming packets to this port number (required).
 -h host   Forward incoming packets to this host (required).
 -p port   Receive packets to forward on this port number (default is to
           pick a port for you).
 -s size   Maximum packet size (default 65536 bytes).
 -v        Verbose mode, outputs more information (default off).
 -r seed   Set the random seed for the program (defaults to current time).
           This can be used to force repeatable experiments (modulo thread
           scheduling differences).
 -d prob   Set the probability of each packet being delayed (default 0).
           This is a floating point number between 0.0 and 100.0.
 -t range  The range of possible delay times in seconds (defaults to 0.5-10
           seconds).  This must be specified in the form min-max with no
           spaces between min, -, and max.
 -l prob   Set the probability of each packet being lost (default 0).
           This is a floating point number between 0.0 and 100.0.
 -e prob   Set the probability of each bit having an error (default 0).
           This is a floating point number between 0.0 and 100.0.

Note:
 Since packets are transmitted UDP, there is still a chance for delays, 
 loss, or errors when all probabilities are 0 due to network conditions!
