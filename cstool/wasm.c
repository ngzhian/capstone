#include <string.h>
#include <ctype.h>
#include <capstone/capstone.h>
#include <emscripten.h>

static struct {
  const char *name;
  cs_arch arch;
  cs_mode mode;
} all_archs[] = {
  { "arm", CS_ARCH_ARM, CS_MODE_ARM },
  { "armb", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
  { "armbe", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
  { "arml", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
  { "armle", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
  { "armv8", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8 },
  { "thumbv8", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_V8 },
  { "armv8be", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8 | CS_MODE_BIG_ENDIAN },
  { "thumbv8be", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_BIG_ENDIAN },
  { "cortexm", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS },
  { "thumb", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB },
  { "thumbbe", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN },
  { "thumble", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN },
  { "arm64", CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN },
  { "arm64be", CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN },
  { "mips", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN },
  { "mipsmicro", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_MICRO },
  { "mipsbemicro", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_MICRO | CS_MODE_BIG_ENDIAN },
  { "mipsbe32r6", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN},
  { "mipsbe32r6micro", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN | CS_MODE_MICRO },
  { "mips32r6", CS_ARCH_MIPS, CS_MODE_MIPS32R6 },
  { "mips32r6micro", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_MICRO },
  { "mipsbe", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
  { "mips64", CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN },
  { "mips64be", CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN },
  { "x16", CS_ARCH_X86, CS_MODE_16 }, // CS_MODE_16
  { "x16att", CS_ARCH_X86, CS_MODE_16 }, // CS_MODE_16 , CS_OPT_SYNTAX_ATT
  { "x32", CS_ARCH_X86, CS_MODE_32 }, // CS_MODE_32
  { "x32att", CS_ARCH_X86, CS_MODE_32 }, // CS_MODE_32, CS_OPT_SYNTAX_ATT
  { "x64", CS_ARCH_X86, CS_MODE_64 }, // CS_MODE_64
  { "x64att", CS_ARCH_X86, CS_MODE_64 }, // CS_MODE_64, CS_OPT_SYNTAX_ATT
  { "ppc32", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_LITTLE_ENDIAN },
  { "ppc32be", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN },
  { "ppc33qpx", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_QPX | CS_MODE_LITTLE_ENDIAN },
  { "ppc32beqpx", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_QPX | CS_MODE_BIG_ENDIAN },
  { "ppc32ps", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_PS | CS_MODE_LITTLE_ENDIAN },
  { "ppc32beps", CS_ARCH_PPC, CS_MODE_32 | CS_MODE_PS | CS_MODE_BIG_ENDIAN },
  { "ppc64", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
  { "ppc64be", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN },
  { "ppc64qpx", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_QPX | CS_MODE_LITTLE_ENDIAN },
  { "ppc64beqpx", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_QPX | CS_MODE_BIG_ENDIAN },
  { "sparc", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN },
  { "sparcv9", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN | CS_MODE_V9 },
  { "systemz", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
  { "sysz", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
  { "s390x", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
  { "xcore", CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN },
  { "m68k", CS_ARCH_M68K, CS_MODE_BIG_ENDIAN },
  { "m68k40", CS_ARCH_M68K, CS_MODE_M68K_040 },
  { "tms320c64x", CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN },
  { "m6800", CS_ARCH_M680X, CS_MODE_M680X_6800 },
  { "m6801", CS_ARCH_M680X, CS_MODE_M680X_6801 },
  { "m6805", CS_ARCH_M680X, CS_MODE_M680X_6805 },
  { "m6808", CS_ARCH_M680X, CS_MODE_M680X_6808 },
  { "m6809", CS_ARCH_M680X, CS_MODE_M680X_6809 },
  { "m6811", CS_ARCH_M680X, CS_MODE_M680X_6811 },
  { "cpu12", CS_ARCH_M680X, CS_MODE_M680X_CPU12 },
  { "hd6301", CS_ARCH_M680X, CS_MODE_M680X_6301 },
  { "hd6309", CS_ARCH_M680X, CS_MODE_M680X_6309 },
  { "hcs08", CS_ARCH_M680X, CS_MODE_M680X_HCS08 },
  { "evm", CS_ARCH_EVM, 0 },
  { "wasm", CS_ARCH_WASM, 0 },
  { "bpf", CS_ARCH_BPF, CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC },
  { "bpfbe", CS_ARCH_BPF, CS_MODE_BIG_ENDIAN | CS_MODE_BPF_CLASSIC },
  { "ebpf", CS_ARCH_BPF, CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED },
  { "ebpfbe", CS_ARCH_BPF, CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED },
  { "riscv32", CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC },
  { "riscv64", CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC },
  { "6502", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_6502 },
  { "65c02", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_65C02 },
  { "w65c02", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_W65C02 },
  { "65816", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_65816_LONG_MX },
  { NULL }
};

// convert hexchar to hexnum
static uint8_t char_to_hexnum(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}

	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + c - 'a');
	}

	//  c >= 'A' && c <= 'F'
	return (uint8_t)(10 + c - 'A');
}

// convert user input (char[]) to uint8_t[], each element of which is
// valid hexadecimal, and return actual length of uint8_t[] in @size.
static uint8_t *preprocess(char *code, size_t *size)
{
	size_t i = 0, j = 0;
	uint8_t high, low;
	uint8_t *result;

	if (strlen(code) == 0)
		return NULL;

	result = (uint8_t *)malloc(strlen(code));
	if (result != NULL) {
		while (code[i] != '\0') {
			if (isxdigit(code[i]) && isxdigit(code[i+1])) {
				high = 16 * char_to_hexnum(code[i]);
				low = char_to_hexnum(code[i+1]);
				result[j] = high + low;
				i++;
				j++;
			}
			i++;
		}
		*size = j;
	}

	return result;
}

int foo(char* mode, char* input)
{
  int i;
  cs_err err;
  csh handle;
  cs_arch arch = CS_ARCH_ALL;
  cs_mode md;
  for (i = 0; all_archs[i].name; i++) {
    if (!strcmp(all_archs[i].name, mode)) {
      arch = all_archs[i].arch;
      err = cs_open(all_archs[i].arch, all_archs[i].mode, &handle);
      if (!err) {
        md = all_archs[i].mode;
        if (strstr (mode, "att")) {
          cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        }
      }
      break;
    }
  }

  if (arch == CS_ARCH_ALL) {
    printf("ERROR: Invalid <arch+mode>: \"%s\", quit!\n", mode);
    return -1;
  }

  uint64_t address = 0LL;
  cs_insn *insn;
  size_t count;
  size_t size;

  uint8_t* assembly = preprocess(input, &size);

  count = cs_disasm(handle, assembly, size, address, 0, &insn);

  if (count > 0) {
    for (size_t i = 0; i < count; i++) {
      EM_ASM({
        addtodiv($0, $1);
      }, insn[i].mnemonic, insn[i].op_str);

    }
    cs_free(insn, count);
    return 0;
  } else {
    printf("ERROR: invalid assembly code\n");
    return(-4);
  }
}
