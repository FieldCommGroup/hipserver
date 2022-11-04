/*
   minimal_gpio.c
   2019-07-03
   Public Domain
*/

/*
   build original file: 'rename' reset to 'main'
   gcc -o minimal_gpio minimal_gpio.c
   sudo ./minimal_gpio
*/

#include <factory_reset.h>

void gpioSetMode(unsigned gpio, unsigned mode)
{
   int reg, shift;

   reg   =  gpio/10;
   shift = (gpio%10) * 3;

   gpioReg[reg] = (gpioReg[reg] & ~(7<<shift)) | (mode<<shift);
}

int gpioGetMode(unsigned gpio)
{
   int reg, shift;

   reg   =  gpio/10;
   shift = (gpio%10) * 3;

   return (*(gpioReg + reg) >> shift) & 7;
}

void gpioSetPullUpDown(unsigned gpio, unsigned pud)
{
   int shift = (gpio & 0xf) << 1;
   uint32_t bits;
   uint32_t pull;

   if (pi_is_2711)
   {
      switch (pud)
      {
         case PI_PUD_OFF:  pull = 0; break;
         case PI_PUD_UP:   pull = 1; break;
         case PI_PUD_DOWN: pull = 2; break;
      }

      bits = *(gpioReg + GPPUPPDN0 + (gpio>>4));
      bits &= ~(3 << shift);
      bits |= (pull << shift);
      *(gpioReg + GPPUPPDN0 + (gpio>>4)) = bits;
   }
   else
   {
      *(gpioReg + GPPUD) = pud;

      usleep(20);

      *(gpioReg + GPPUDCLK0 + PI_BANK) = PI_BIT;

      usleep(20);
  
      *(gpioReg + GPPUD) = 0;

      *(gpioReg + GPPUDCLK0 + PI_BANK) = 0;
   }
}

int gpioRead(unsigned gpio)
{
   if ((*(gpioReg + GPLEV0 + PI_BANK) & PI_BIT) != 0) return 1;
   else                                         return 0;
}

void gpioWrite(unsigned gpio, unsigned level)
{
   if (level == 0) *(gpioReg + GPCLR0 + PI_BANK) = PI_BIT;
   else            *(gpioReg + GPSET0 + PI_BANK) = PI_BIT;
}

void gpioTrigger(unsigned gpio, unsigned pulseLen, unsigned level)
{
   if (level == 0) *(gpioReg + GPCLR0 + PI_BANK) = PI_BIT;
   else            *(gpioReg + GPSET0 + PI_BANK) = PI_BIT;

   usleep(pulseLen);

   if (level != 0) *(gpioReg + GPCLR0 + PI_BANK) = PI_BIT;
   else            *(gpioReg + GPSET0 + PI_BANK) = PI_BIT;
}

/* Bit (1<<x) will be set if gpio x is high. */

uint32_t gpioReadBank1(void) { return (*(gpioReg + GPLEV0)); }
uint32_t gpioReadBank2(void) { return (*(gpioReg + GPLEV1)); }

/* To clear gpio x bit or in (1<<x). */

void gpioClearBank1(uint32_t bits) { *(gpioReg + GPCLR0) = bits; }
void gpioClearBank2(uint32_t bits) { *(gpioReg + GPCLR1) = bits; }

/* To set gpio x bit or in (1<<x). */

void gpioSetBank1(uint32_t bits) { *(gpioReg + GPSET0) = bits; }
void gpioSetBank2(uint32_t bits) { *(gpioReg + GPSET1) = bits; }

unsigned gpioHardwareRevision(void)
{
   static unsigned rev = 0;

   FILE *filp;
   char buf[512];
   char term;
   int chars=4; /* number of chars in revision string */

   filp = fopen ("/proc/cpuinfo", "r");

   if (filp != NULL)
   {
      while (fgets(buf, sizeof(buf), filp) != NULL)
      {
         if (!strncasecmp("revision", buf, 8))
         {
            if (sscanf(buf+strnlen_s(buf, sizeof(buf))-(chars+1),
               "%x%c", &rev, &term) == 2)
            {
               if (term != '\n') rev = 0;
               else rev &= 0xFFFFFF; /* mask out warranty bit */
            }
         }
      }

      fclose(filp);
   }

   if (filp = fopen("/proc/device-tree/soc/ranges" , "rb"))
   {
      if (fread(buf, 1, sizeof(buf), filp) >= 8)
      {
         piPeriphBase = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
         if (!piPeriphBase)
            piPeriphBase = buf[8]<<24 | buf[9]<<16 | buf[10]<<8 | buf[11];

         if (piPeriphBase == 0xFE00000) pi_is_2711 = 1;
      }
      fclose(filp);
   }

   return rev;
}

/* Returns the number of microseconds after system boot. Wraps around
   after 1 hour 11 minutes 35 seconds.
*/

uint32_t gpioTick(void) { return systReg[SYST_CLO]; }


/* Map in registers. */

static uint32_t * initMapMem(int fd, uint32_t addr, uint32_t len)
{
    return (uint32_t *) mmap(0, len,
       PROT_READ|PROT_WRITE,
//       PROT_READ|PROT_WRITE|PROT_EXEC,
       MAP_SHARED|MAP_LOCKED,
       fd, addr);
}

int gpioInitialise(void)
{
   int fd;

   gpioHardwareRevision(); /* sets rev and peripherals base address */

   fd = open("/dev/mem", O_RDWR | O_SYNC) ;

   if (fd < 0)
   {
      fprintf(stderr,
         "This program needs root privileges.  Try using sudo\n");
      return -1;
   }

   gpioReg  = initMapMem(fd, GPIO_BASE,  GPIO_LEN);
   systReg  = initMapMem(fd, SYST_BASE,  SYST_LEN);
   bscsReg  = initMapMem(fd, BSCS_BASE,  BSCS_LEN);

   close(fd);

   if ((gpioReg == MAP_FAILED) ||
       (systReg == MAP_FAILED) ||
       (bscsReg == MAP_FAILED))
   {
      fprintf(stderr,
         "Bad, mmap failed\n");
      return -1;
   }
   return 0;
}

#define WRITE_PROTECT_PIN (3)

int write_protect()
{
 // place holder for pin 3 - was reset
    int i;

    // gpioInitialized moved to main()

   int pin = WRITE_PROTECT_PIN;

   int write_protect_state = !gpioRead(pin);


   return write_protect_state;

}

int writeProtectSet()
{
   int writeProtectCd = 0;

#if !defined(__x86_64__)
   writeProtectCd = write_protect();
#endif

   return (writeProtectCd != 0);
}

#define FACTORY_RESET_PIN (2)
// return  
//  1 for reset state active
//  0 for reset state inactive
int reset()
{
   int i;

    // gpioInitialized moved to main()

   // get state of GPIO 3 - factory reset pin
   // default is internally pulled high, factory reset state is low using a jumper to gnd
   int pin = FACTORY_RESET_PIN;
   //printf("Factory reset pin gpio=%d level=%d\n", pin,  gpioRead(pin));
   int reset_state = !gpioRead(pin);
   /*  DEBUG
	if (reset_state)
	{
      		printf("Factory reset enabled TODO remove config files now.\n");

	}
   */
   /* Original code to output state of all pins
   for (i=0; i<54; i++)
   {
      printf("gpio=%d tick=%u mode=%d level=%d\n",
         i, gpioTick(), gpioGetMode(i), gpioRead(i));
   }

   for (i=0; i<16; i++)
   {
      printf("reg=%d val=%8X\n",
         i, bscsReg[i]);
   }
   */
   return reset_state;
}


