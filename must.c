#define _REENTRANT
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>

/* Set up NANOSEC if it does not exist on the system. */

#ifndef NANOSEC
#define NANOSEC 1000000000L
#endif

/* Program settings. */

int local_port = 0;
int forward_port = -1;
char *forward_host = NULL;
int max_size  = 65536;
int verbose = 0;
int random_seed;
double delay_probability = 0;
double min_delay = 0.5;
double max_delay = 10.0;
double loss_probability = 0;
double error_probability = 0;
double copy_probability = 0;
char *program_name;

/* Socket stuff. */

char hostname[256];
int forward_socket;
struct sockaddr_in forward_address;
socklen_t forward_address_len;
pthread_mutex_t forward_mutex;
int return_socket;
struct sockaddr_in return_address;
socklen_t return_address_len;
pthread_mutex_t return_mutex;
struct sockaddr_in forward_dest;
socklen_t forward_dest_len;
struct sockaddr_in return_dest;
socklen_t return_dest_len;
int copy_socket;
struct sockaddr_in copy_address;
socklen_t copy_address_len;
pthread_mutex_t copy_mutex;

/* Delay information. */

struct delayed_packet_t {
  int number;
  double delay;
  unsigned char *buffer;
  int amount;
};

void usage(int argc, char *argv[]) {

  fprintf(stderr, "MUST:  Mike's UDP Simulator Tool\n\n");
  fprintf(stderr, "Usage: %s [options]\n", argv[0]);
  fprintf(stderr, "\nOptions:\n");
  fprintf(stderr, " -f port   Forward incoming packets to this port number (required).\n");
  fprintf(stderr, " -h host   Forward incoming packets to this host (required).\n");
  fprintf(stderr, " -p port   Receive packets to forward on this port number (default is to\n");
  fprintf(stderr, "           pick a port for you).\n");
  fprintf(stderr, " -s size   Maximum packet size (default 65536 bytes).\n");
  fprintf(stderr, " -v        Verbose mode, outputs more information (default off).\n");
  fprintf(stderr, " -r seed   Set the random seed for the program (defaults to current time).\n");
  fprintf(stderr, "           This can be used to force repeatable experiments (modulo thread\n");
  fprintf(stderr, "           scheduling differences).\n");
  fprintf(stderr, " -d prob   Set the probability of each packet being delayed (default 0).\n");
  fprintf(stderr, "           This is a floating point number between 0.0 and 100.0.\n");
  fprintf(stderr, " -t range  The range of possible delay times in seconds (defaults to 0.5-10\n");
  fprintf(stderr, "           seconds).  This must be specified in the form min-max with no\n");
  fprintf(stderr, "           spaces between min, -, and max.\n");
  fprintf(stderr, " -l prob   Set the probability of each packet being lost (default 0).\n");
  fprintf(stderr, "           This is a floating point number between 0.0 and 100.0.\n");
  fprintf(stderr, " -e prob   Set the probability of each bit having an error (default 0).\n");
  fprintf(stderr, "           This is a floating point number between 0.0 and 100.0.\n");
  fprintf(stderr, " -c prob   Set the probability of each packed being copied (default 0).\n");
  fprintf(stderr, "           This is a floating point number between 0.0 and 100.0\n");
  fprintf(stderr, "           Copies may be delayed, lost, or have errors added like regular\n");
  fprintf(stderr, "           data packets as well.\n");
  fprintf(stderr, "\nNotes:\n");
  fprintf(stderr, " Since packets are transmitted UDP, there is still a chance for delays, \n");
  fprintf(stderr, " loss, or errors when all probabilities are 0 due to network conditions!\n");
  fprintf(stderr, " Also, it is possible to run out of memory if very large packets are used\n");
  fprintf(stderr, " and large and frequent delays in transmission are being used (the data\n");
  fprintf(stderr, " has to be buffered somewhere during the delays!).  If you experience \"Out\n");
  fprintf(stderr, " of memory\" errors, adjust program options accordingly!\n");
  return;
}

void cleanup(int unused) {

  close(forward_socket);
  close(return_socket);

  exit(0);
}

int get_udp_socket(int port, int *s, struct sockaddr_in *addr, socklen_t *len) {

  struct sockaddr_in address;

  if ((*s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror(program_name);
    fprintf(stderr, "%s:  Could not create socket!\n", program_name);
    close(*s);
    return -1;
  }
  address.sin_family = AF_INET;
  address.sin_port = htons((unsigned short) port);
  address.sin_addr.s_addr = INADDR_ANY;
  if (bind(*s, (struct sockaddr *) &address, sizeof(address)) < 0) {
    perror(program_name);
    fprintf(stderr, "%s:  Could not bind socket!\n", program_name);
    close(*s);
    return -1;
  }
  *len = sizeof(struct sockaddr_in);
  if (getsockname(*s, (struct sockaddr *) addr, len) < 0) {
    perror(program_name);
    fprintf(stderr, "%s:  Could not retrieve socket information!\n", program_name);
    close(*s);
    return -1;
  }
  return 0;
}

ssize_t protected_recvfrom(int s, void *mesg, size_t len, int flags, 
			   struct sockaddr *from, socklen_t *fromlen, pthread_mutex_t mutex) {

  ssize_t val;

  pthread_mutex_lock(&mutex);
  val = recvfrom(s, mesg, len, flags, from, fromlen);
  pthread_mutex_unlock(&mutex);

  return val;
}

ssize_t protected_sendto(int s, void *mesg, size_t len, int flags, 
			 struct sockaddr *to, int tolen, pthread_mutex_t mutex) {

  ssize_t val;

  pthread_mutex_lock(&mutex);
  val = sendto(s, mesg, len, flags, to, tolen);
  pthread_mutex_unlock(&mutex);

  return val;
}

int return_setup = 0;

void *delayed_forward(void *dp_void) {

  struct delayed_packet_t *dp;
  struct timespec delay_time;
  double int_part, frac_part;
  int amount;

  dp = (struct delayed_packet_t *) dp_void;
  frac_part = modf(dp->delay, &int_part);
  delay_time.tv_sec = (long) int_part;
  delay_time.tv_nsec = (long) (frac_part * NANOSEC);
  nanosleep(&delay_time, NULL);

  if ((amount = protected_sendto(return_socket, dp->buffer, dp->amount, 0, (struct sockaddr *) &forward_dest, forward_dest_len, return_mutex)) < 0) {
    fprintf(stderr, "%s:  Error sending data, attempting to continue.\n", program_name);
  }
  if (verbose) {
    printf("Delayed packet %d forwarded\n", dp->number);
  }

  free(dp->buffer);
  free(dp);

  return NULL;
}

void *delayed_return(void *dp_void) {

  struct delayed_packet_t *dp;
  struct timespec delay_time;
  double int_part, frac_part;
  int amount;

  dp = (struct delayed_packet_t *) dp_void;
  frac_part = modf(dp->delay, &int_part);
  delay_time.tv_sec = (long) int_part;
  delay_time.tv_nsec = (long) (frac_part * NANOSEC);
  nanosleep(&delay_time, NULL);

  if ((amount = protected_sendto(forward_socket, dp->buffer, dp->amount, 0, (struct sockaddr *) &return_dest, return_dest_len, forward_mutex)) < 0) {
    fprintf(stderr, "%s:  Error sending data, attempting to continue.\n", program_name);
  }
  if (verbose) {
    printf("Delayed packet %d forwarded\n", dp->number);
  }

  free(dp->buffer);
  free(dp);

  return NULL;
}

void *return_data(void *unused) {

  struct sockaddr_in from;
  socklen_t from_len;
  unsigned char *buffer;
  int amount;
  int count = 0;
  struct delayed_packet_t *dp;
  pthread_t delay_thread;
  int mean_bits_between_error;
  int bits_before_error;
  int packet_bits;
  int next_bit_error;
  int error_bit, error_byte;
  pthread_t return_thread;

  if (verbose) {
    printf("Return thread spawned.\n");
  }
  if (error_probability != 0.0) {
    mean_bits_between_error = (int)(1.0/(error_probability/100.0));
    bits_before_error = lrand48() % (2 * mean_bits_between_error);
    next_bit_error = bits_before_error;
    if (verbose) {
      printf("First return error in %d bits\n", bits_before_error);
    }
  }
  if ((buffer = (unsigned char *) malloc(sizeof(char) * max_size)) == NULL) {
    fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
    cleanup(0);
  }
  while(1) {
    if ((amount = recvfrom(return_socket, buffer, max_size, 0, (struct sockaddr *) &from, &from_len)) < 0) {
      if (errno == EBADF) {
	return NULL;
      }
      fprintf(stderr, "%s:  Error receiving data, attempting to continue.\n", program_name);
      continue;
    }
    count++;
    if (verbose) {
      printf("Packet %d received to return:\n", count);
    }
    if (drand48()*100.0 <= copy_probability) {
      if ((amount = protected_sendto(copy_socket, buffer, amount, 0, (struct sockaddr *) &return_address, return_address_len, copy_mutex)) < 0) {
	fprintf(stderr, "%s:  Error copying data, attempting to continue.\n", program_name);
	continue;
      }
      if (verbose) {
	printf("  Packet copied ... will see it again soon!\n");
      }
    }
    if (drand48()*100.0 <= loss_probability) {
      if (verbose) {
	printf("  Packet lost\n");
      }
      continue;
    }
    if (error_probability != 0) {
      packet_bits = amount * 8;
      error_byte = 0;
      while(next_bit_error < packet_bits) {
	if (verbose) {
	  printf("  Error inserted at bit %d\n", next_bit_error);
	}
	error_byte = next_bit_error / 8;
	if (error_byte >= amount) {
	  error_byte = amount-1;
	}
	error_bit = next_bit_error % 8;
	buffer[error_byte] = buffer[error_byte] ^ (1 << error_bit);
	bits_before_error = lrand48() % (2 * mean_bits_between_error);
	next_bit_error += bits_before_error;
	if (verbose) {
	  printf("  Next return error in %d bits\n", bits_before_error);
	}
      }
      bits_before_error = next_bit_error - packet_bits;
      next_bit_error = bits_before_error;
    }
    if (drand48()*100.0 <= delay_probability) {
      if ((dp = (struct delayed_packet_t *) malloc(sizeof(struct delayed_packet_t))) == NULL) {
	fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
	cleanup(0);
      }
      dp->number = count;
      dp->delay = (drand48()*(max_delay-min_delay))+min_delay;
      dp->amount = amount;
      if ((dp->buffer = (unsigned char *) malloc(sizeof(unsigned char) * amount)) == NULL) {
	fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
	cleanup(0);
      }
      bcopy(buffer, dp->buffer, amount);
      if (verbose) {
	printf("  Delayed %lf seconds\n", dp->delay);
      }
      if (pthread_create(&delay_thread, NULL, delayed_return, dp) != 0) {
	fprintf(stderr, "%s:  Error delaying packet, dropping instead!\n", program_name);
      }
      continue;
    }
    if ((amount = protected_sendto(forward_socket, buffer, amount, 0, (struct sockaddr *) &return_dest, return_dest_len, forward_mutex)) < 0) {
      fprintf(stderr, "%s:  Error sending data, attempting to continue.\n", program_name);
      continue;
    }
    if (verbose) {
      printf("  Packet forwarded\n");
    }
  }
}

void forward_data() {

  struct sockaddr_in from;
  socklen_t from_len;
  unsigned char *buffer;
  int amount;
  int count = 0;
  struct hostent *hp;
  struct delayed_packet_t *dp;
  pthread_t delay_thread;
  int mean_bits_between_error;
  int bits_before_error;
  int next_bit_error;
  int packet_bits;
  int error_bit, error_byte;
  pthread_t return_thread;

  if (error_probability != 0.0) {
    mean_bits_between_error = (int)(1.0/(error_probability/100.0));
    bits_before_error = lrand48() % (2 * mean_bits_between_error);
    next_bit_error = bits_before_error;
    if (verbose) {
      printf("First error in %d bits\n", next_bit_error);
    }
  }
  if ((hp = gethostbyname(forward_host)) == NULL) {
    fprintf(stderr, "%s:  Host %s not found!\n", program_name, forward_host);
    cleanup(0);
  }
  bcopy(hp->h_addr, &forward_dest.sin_addr, hp->h_length);
  forward_dest.sin_family = AF_INET;
  forward_dest.sin_port = htons(forward_port);
  forward_dest_len = sizeof(forward_dest);
  if ((buffer = (unsigned char *) malloc(sizeof(char) * max_size)) == NULL) {
    fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
    cleanup(0);
  }
  from_len = sizeof(struct sockaddr_in);
  while(1) {
    if ((amount = recvfrom(forward_socket, buffer, max_size, 0, (struct sockaddr *) &from, &from_len)) < 0) {
      if (errno == EBADF) {
	return;
      }
      fprintf(stderr, "%s:  Error receiving data, attempting to continue.\n", program_name);
      continue;
    }
    count++;
    if (verbose) {
      printf("Packet %d received:\n", count);
    }
    if (return_setup == 0) {
      return_setup = 1;
      return_dest = from;
      return_dest_len = from_len;
      pthread_create(&return_thread, NULL, return_data, NULL);
    }
    if (drand48()*100.0 <= copy_probability) {
      if ((amount = protected_sendto(copy_socket, buffer, amount, 0, (struct sockaddr *) &forward_address, forward_address_len, copy_mutex)) < 0) {
	fprintf(stderr, "%s:  Error copying data, attempting to continue.\n", program_name);
	continue;
      }
      if (verbose) {
	printf("  Packet copied ... will see it again soon!\n");
      }
    }
    if (drand48()*100.0 <= loss_probability) {
      if (verbose) {
	printf("  Packet lost\n");
      }
      continue;
    } 
    if (error_probability != 0) {
      packet_bits = amount * 8;
      error_byte = 0;
      while(next_bit_error < packet_bits) {
	if (verbose) {
	  printf("  Error inserted at bit %d\n", next_bit_error);
	}
	error_byte = next_bit_error / 8;
	if (error_byte >= amount) {
	  error_byte = amount-1;
	}
	error_bit = next_bit_error % 8;
	buffer[error_byte] = buffer[error_byte] ^ (1 << error_bit);
	bits_before_error = lrand48() % (2 * mean_bits_between_error);
        next_bit_error += bits_before_error;
	if (verbose) {
	  printf("  Next error in %d bits\n", bits_before_error);
	}
      }
      bits_before_error = next_bit_error - packet_bits;
      next_bit_error = bits_before_error;
    }
    if (drand48()*100.0 <= delay_probability) {
      if ((dp = (struct delayed_packet_t *) malloc(sizeof(struct delayed_packet_t))) == NULL) {
	fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
	cleanup(0);
      }
      dp->number = count;
      dp->delay = (drand48()*(max_delay-min_delay))+min_delay;
      dp->amount = amount;
      if ((dp->buffer = (unsigned char *) malloc(sizeof(unsigned char) * amount)) == NULL) {
	fprintf(stderr, "%s:  Out of memory ... aborting!\n", program_name);
	cleanup(0);
      }
      bcopy(buffer, dp->buffer, amount);
      if (verbose) {
	printf("  Delayed %lf seconds\n", dp->delay);
      }
      if (pthread_create(&delay_thread, NULL, delayed_forward, dp) != 0) {
	fprintf(stderr, "%s:  Error delaying packet, dropping instead!\n", program_name);
      }
      continue;
    }
    if ((amount = protected_sendto(return_socket, buffer, amount, 0, (struct sockaddr *) &forward_dest, forward_dest_len, return_mutex)) < 0) {
      fprintf(stderr, "%s:  Error sending data, attempting to continue.\n", program_name);
      continue;
    }
    if (verbose) {
      printf("  Packet forwarded\n");
    }
  }
}

int main(int argc, char *argv[]) {

  int count;
  struct sockaddr_in address;
  int address_len;

  /* Pre-initialize some global variables. */

  random_seed = time(NULL);

  /* Process command line arguments. */

  program_name = strdup(argv[0]);
  if (argc == 1) {
    usage(argc, argv);
    return 1;
  }
  for (count = 1; count < argc; count++) {
    if (argv[count][0] == '-') {
      switch(argv[count][1]) {
      case 'f':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	forward_port = atoi(argv[count]);
	break;

      case 'p':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	local_port = atoi(argv[count]);
	break;

      case 's':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	max_size = atoi(argv[count]);
	break;

      case 'r':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	random_seed = atoi(argv[count]);
	break;

      case 'd':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	delay_probability = atof(argv[count]);
	break;

      case 'l':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	loss_probability = atof(argv[count]);
	break;

      case 'e':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	error_probability = atof(argv[count]);
	break;

      case 'c':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	copy_probability = atof(argv[count]);
	break;

      case 't':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	if (sscanf(argv[count], "%lf-%lf", &min_delay, &max_delay) != 2) {
	  usage(argc, argv);
	  return 1;
	}
	break;

      case 'h':
	count++;
	if (count == argc) {
	  usage(argc, argv);
	  return 1;
	}
	forward_host = strdup(argv[count]);
	break;

      case 'v':
	verbose = 1;
	break;

      default:
	usage(argc, argv);
	return 1;
      }
    } else {
      usage(argc, argv);
      return 1;
    }
  }

  /* Check for required options. */

  if (forward_port < 0) {
    fprintf(stderr, "%s:  Must specify port to forward to using -p option!\n", argv[0]);
    return 1;
  }
  if (forward_host == NULL) {
    fprintf(stderr, "%s:  Must specify host to forward to using -h option!\n", argv[0]);
    return 1;
  }
  if (max_size < 0) {
    fprintf(stderr, "%s:  Maximum packet size must be greater than 0!\n", argv[0]);
    return 1;
  }
  if ((delay_probability < 0.0) || (delay_probability > 100.0)) {
    fprintf(stderr, "%s:  Invalid delay probability!\n", argv[0]);
    return 1;
  }
  if ((loss_probability < 0.0) || (loss_probability > 100.0)) {
    fprintf(stderr, "%s:  Invalid delay probability!\n", argv[0]);
    return 1;
  }
  if ((error_probability < 0.0) || (error_probability > 100.0)) {
    fprintf(stderr, "%s:  Invalid error probability!\n", argv[0]);
    return 1;
  }
  if ((copy_probability < 0.0) || (copy_probability > 100.0)) {
    fprintf(stderr, "%s:  Invalid copy probability!\n", argv[0]);
    return 1;
  }
  if ((min_delay < 0.0) || (min_delay > max_delay)) {
    fprintf(stderr, "%s:  Invalid delay time range!\n", argv[0]);
    return 1;
  }

  /* Initialize some stuff. */

  srand48(random_seed);
  gethostname(hostname, 256);

  /* If verbose, print out current settings. */

  if (verbose) {
    printf("MUST options:\n");
    printf("  Forwarding to port %d on host %s\n", forward_port, forward_host);
    if (local_port == 0) {
      printf("  Receiving packets on port to be selected\n");
    } else {
      printf("  Receiving packets on port %d\n", local_port);
    }
    printf("  Maximum packet size %d\n", max_size);
    printf("  Random seed %d\n", random_seed);
    printf("  Delay probability %lf\n", delay_probability);
    printf("  Delay time range %lf to %lf seconds\n", min_delay, max_delay);
    printf("  Loss probability %lf\n", loss_probability);
    printf("  Error probability %lf\n", error_probability);
  }

  /* Create sockets. */

  if (get_udp_socket(local_port, &forward_socket, &forward_address, &forward_address_len) < 0) {
    return 2;
  }
  if (get_udp_socket(0, &return_socket, &return_address, &return_address_len) < 0) {
    return 2;
  }
  if (get_udp_socket(0, &copy_socket, &copy_address, &copy_address_len) < 0) {
    return 2;
  }

  /* Set up mutexes. */

  if (pthread_mutex_init(&forward_mutex, NULL) != 0) {
    fprintf(stderr, "%s:  Unable to create mutex!\n", argv[0]);
    return 3;
  }
  if (pthread_mutex_init(&return_mutex, NULL) != 0) {
    fprintf(stderr, "%s:  Unable to create mutex!\n", argv[0]);
    return 3;
  }
  if (pthread_mutex_init(&copy_mutex, NULL) != 0) {
    fprintf(stderr, "%s:  Unable to create mutex!\n", argv[0]);
    return 3;
  }

  /* If picking port, inform user. */

  if (local_port == 0) {
    printf("To forward data, send to port %d on host %s\n", ntohs(forward_address.sin_port), hostname);
  }

  /* If verbose, report ports. */

  if (verbose) {
    printf("Ports created:\n");
    printf("  Forwarding port %d on %s\n", ntohs(forward_address.sin_port), hostname);
    printf("  Returning port %d on %s\n", ntohs(return_address.sin_port), hostname);
    printf("  Copying port %d on %s\n", ntohs(copy_address.sin_port), hostname);
  }

  /* Now do the forwarding. */

  signal(SIGTERM, cleanup);
  signal(SIGQUIT, cleanup);
  signal(SIGINT, cleanup);
  if (verbose) {
    printf("Beginning forwarding:\n");
  }
  forward_data();

  return 0;
}
