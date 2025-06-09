#include <stdbool.h>
#include <stdio.h>
#include <string.h>
// Below provides "EXIT_SUCCESS"
#include <stdbool.h>

#ifdef F_CPU
#undef F_CPU
#endif

#define F_CPU 16000000

#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <avr/sleep.h>

static int uart_putchar(char c, FILE *stream) {
  if (c == '\n')
    uart_putchar('\r', stream);
  loop_until_bit_is_set(UCSR0A, UDRE0);
  UDR0 = c;
  return 0;
}

static FILE mystdout = FDEV_SETUP_STREAM(uart_putchar, NULL, _FDEV_SETUP_WRITE);

#define PASSWORD "pass"

// Password input max length:
#define MAX_LENGTH 10

int main() {
  stdout = &mystdout;

  // unable to get input from stdin with simavr AFAIK
  char *input = "pass\n";
  printf("Enter the password (max %d characters): ", MAX_LENGTH);

  bool password_correct = false;

  if (strchr(input, '\n') == NULL) {
    password_correct = false;
  } else {
    // Remove the newling character
    input[strcspn(input, "\n")] = '\0';

    // NOTICE: fgets and strchr make sure the passowrd
    //      is the correct length so strcmp is safe :)
    if (strcmp(input, PASSWORD) == 0) {
      password_correct = true;
    }
  }

  // Compare the input with the predefined password
  if (password_correct == 1) {
    printf("Correct\n");
    // return EXIT_SUCCESS;
  } else {
    printf("Wrong\n%s", input);
    // return 97;
  }

  // this quits the simulator, since interrupts are off
  // this is a "feature" that allows running tests cases and exit
  // sleep_cpu();
  return 0;
}
