import stream
from pointer import Pointer
from const_buffer import ConstBuffer
from utils import Utils


class InstructionPrefix:
    prefixes_to_ignore = [
        0xF0,  # LOCK prefix
        0x2E,  # CS segment override - ignored in 64-bit mode
        0x36,  # SS segment override - ignored in 64-bit mode
        0x3E,  # DS segment override - ignored in 64-bit mode
        0x26,  # ES segment override - ignored in 64-bit mode
        0x2E,  # Branch not taken
        0x3E,  # Branch taken
    ]

    def __init__(self, stream):
        self.operand_size_overridden = False
        self.address_size_overridden = False
        self.repe = False
        self.repne = False
        self.segment = "none"

        self.rex_w = 0
        self.reg_extension = 0
        self.rex_x = 0
        self.rex_b = 0

        while True:
            prefix = stream.read()

            if prefix in InstructionPrefix.prefixes_to_ignore:
                pass
            elif (prefix >= 0x40) and (prefix <= 0x4F):  # REX prefix
                self.rex_w = (prefix >> 3) & 1
                self.reg_extension = 8 * ((prefix >> 2) & 1)
                self.rex_x = (prefix >> 1) & 1
                self.rex_b = prefix & 1
            elif prefix == 0x64:  # FS segment override
                self.segment = "FS"
            elif prefix == 0x65:  # GS segment override
                self.segment = "GS"
            elif prefix == 0x66:  # Operand-size override prefix
                self.operand_size_overridden = True
            elif prefix == 0x67:  # Address-size override prefix
                self.address_size_overridden = True
            elif prefix == 0xF2:  # REPNE/REPNZ prefix
                self.repne = True
            elif prefix == 0xF3:  # REP or REPE/REPZ prefix
                self.repe = True
            else:
                # all the prefixes have been read
                stream.back()
                break

    def simd_prefix(self):
        arr = []

        if self.operand_size_overridden:
            arr.append(0x66)

        if self.repne:
            arr.append(0xF2)

        if self.repe:
            arr.append(0xF3)

        if len(arr) > 1:
            raise "only one SIMD prefix expected, but several provided"

        if len(arr) == 0:
            return 0x00

        return arr[0]


class Instruction:
    def __init__(self, stream, cpu, linux):
        self.stream = stream
        self.cpu = cpu
        self.linux = linux

        self.prefix = InstructionPrefix(stream)
        self.opcode = self.read_opcode(stream)
        self._modrm = None

        self.func = None  # operation to be done (e.g. 'add', 'mov' etc.)
        self.size = None  # operand size (in bytes)
        self.args = []    # operation arguments. If operation result is stored
                          # the destination is encoded in the first argument
        self.cond = None  # condition to check for conditional operations
                          # (e.g. 'jne', 'cmovo')

        self.xmm_item_size = None

        if self.prefix.address_size_overridden:
            self.address_size = 4
        else:
            self.address_size = 8

        if self.opcode >= 0x00 and self.opcode <= 0x3F:
            if self.opcode % 8 in [6, 7]:
                raise Exception("bad opcode: 0x%02x" % self.opcode)

            funcs = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
            params = [[BYTE, R_M, REG],
                      [LONG, R_M, REG],
                      [BYTE, REG, R_M],
                      [LONG, REG, R_M],
                      [BYTE, ACC, IM1],
                      [LONG, ACC, IMM]]
            self.decode_arguments([funcs[self.opcode / 8]] + params[self.opcode % 8])
        elif self.opcode >= 0x50 and self.opcode <= 0x57:
            self.func = "push"
            self.size = self.multi_byte()
            self.decode_register_from_opcode()
        elif self.opcode >= 0x58 and self.opcode <= 0x5F:
            self.func = "pop"
            self.size = self.multi_byte()
            self.decode_register_from_opcode()
        elif self.opcode == 0x63:
            self.func = "movsxd"
            self.size = self.multi_byte
            self.args.append(self.modrm().register())
            self.modrm().operand_size = min(4, self.modrm().operand_size)
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x68:
            self.func = "push"
            self.size = self.multi_byte()
            self.decode_immediate_16or32()
        elif self.opcode == 0x6A:
            self.func = "push"
            self.size = 1
            self.decode_immediate_16or32()
        elif self.opcode == 0x0FBE:
            self.func = "movsx"
            self.size = self.multi_byte()
            self.args.append(self.modrm().register())
            self.modrm().operand_size = 1
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x0FBF:
            self.func = "movsx"
            self.size = self.multi_byte()
            self.args.append(self.modrm().register())
            self.modrm().operand_size = 2
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x0FB6:
            self.func = "movzx"
            self.size = self.multi_byte()
            self.args.append(self.modrm().register())
            self.modrm().operand_size = 1
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x0FB7:
            self.func = "movzx"
            self.size = self.multi_byte()
            self.args.append(self.modrm().register())
            self.modrm().operand_size = 2
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode >= 0x70 and self.opcode <= 0x7F:
            self.func = "jmp"
            self.cond = self.opcode % 16
            self.decode_relative_address(1)
        elif self.opcode >= 0x0F80 and self.opcode <= 0x0F8F:
            self.func = "jmp"
            self.cond = self.opcode % 16
            # TODO: are 16-bit offset specified?
            self.decode_relative_address(4)
        elif self.opcode in [0x80, 0x81, 0x83]:
            if self.opcode == 0x80:
                self.size = 1
            else:
                self.size = self.multi_byte()

            funcs = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
            self.func = funcs[self.modrm().opcode_ext()]

            self.args.append(self.modrm().register_or_memory())

            if self.opcode == 0x81:
                self.decode_immediate_16or32()
            else:
                self.decode_immediate(1)
        elif self.opcode == 0x90:
            if self.prefix.repe:
                self.func = "pause"
            else:
                self.func = "nop"
        elif self.opcode >= 0x91 and self.opcode <= 0x97:
            self.func = "xchg"
            self.size = self.multi_byte()
            self.encode_accumulator()
            self.decode_register_from_opcode()
        elif self.opcode >= 0xb0 and self.opcode <= 0xb7:
            self.func = "mov"
            self.size = 1
            self.decode_register_from_opcode()
            self.decode_immediate()
        elif self.opcode >= 0xb8 and self.opcode <= 0xbf:
            sefl.func = "mov"
            self.size = multi_byte
            self.decode_register_from_opcode()
            self.decode_immediate()
        elif self.opcode == 0xC3:
            self.func = "retn"
            self.encode_value(0)
        elif self.opcode in [0xE0, 0xE1, 0xE2]:
            self.func = ["loopnz", "loopz", "loop"][self.opcode - 0xE0]
            self.encode_counter()
            self.decode_relative_address(1)
        elif self.opcode == 0xE8:
            if self.prefix.operand_size_overridden:
                raise "Use of operand-size prefix in 64-bit mode may result in implementation-dependent behaviour"
            self.func = "call"
            self.decode_relative_address(4)
        elif self.opcode == 0xE9:
            if self.prefix.operand_size_overridden:
                raise "Use of operand-size prefix in 64-bit mode may result in implementation-dependent behaviour"
            self.func = "jmp"
            self.decode_relative_address(4)
        elif self.opcode == 0xEB:
            self.func = "jmp"
            self.decode_relative_address(1)
        elif self.opcode == 0xFF:
            ext = self.modrm().opcode_ext()
            if ext == 0:
                self.func = "inc"
                self.size = self.multi_byte()
                self.modrm().operand_size = self.multi_byte()
                self.args.append(modrm().register_or_memory())
                self.encode_value(1)
            elif ext == 1:
                self.func = "dec"
                self.size = self.multi_byte()
                self.modrm().operand_size = self.multi_byte()
                self.args.append(modrm().register_or_memory())
                self.encode_value(1)
            elif ext == 2:
                self.func = "call"
                # TODO: unspecified behaviour for 16 and 32-bit operands
                self.size = self.multi_byte()
                self.modrm().operand_size = self.multi_byte()
                ptr = self.modrm().register_or_memory()
                self.encode_value(ptr.read_int)
            elif ext == 4:
                self.func = "jmp"
                # TODO: unspecified behaviour for 16 and 32-bit operands
                self.size = self.multi_byte()
                self.modrm().operand_size = self.multi_byte()
                ptr = self.modrm().register_or_memory()
                self.encode_value(ptr.read_int)
            else:
                raise "opcode extension not implemented for opcode 0xFF: %d" % ext

        elif self.opcode == 0x0F12:
            if self.prefix.simd_prefix != 0x66:
                raise "not implemtented"

            self.func = "mov"
            self.size = 8
            self.args.append(self.modrm().xmm_register())
            self.args.append(self.modrm().xmm_register_or_memory())
            if self.modrm().mode == 0b11:
                raise "memory expected" 
        elif self.opcode == 0x0F16:
            if self.prefix.simd_prefix != 0x66:
                raise "not implemtented"

            self.func = "mov"
            self.size = 8
            self.args.append(self.modrm().xmm_register())
            self.args.append(self.modrm().xmm_register_or_memory())
            if self.modrm().mode == 0b11:
                raise "memory expected" 
            self.args[0] = Pointer(self.args[0].mem, self.args[0].pos + 8, self.args[0].size)
        elif self.opcode >= 0x0F19 and self.opcode <= 0x0F1F:
            if self.multi_byte() == 8:
                self.size = 4
            else:
                self.size = self.multi_byte()
            self.func = "nop"
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode >= 0x0F40 and self.opcode <= 0x0F4F:
            self.func = "mov"
            self.cond = self.opcode % 16
            self.size = self.multi_byte()
            self.args.append(self.modrm().register())
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x0F6E:
            self.func = "movq"
            self.size = self.mm_or_xmm_operand_size()
            self.args.append(self.modrm().mm_or_xmm_register())
            if self.prefix.rex_w:
                self.size = 8
            else:
                self.size = 4
            self.modrm().operand_size = self.size
            self.args.append(self.modrm().register_or_memory())
        elif self.opcode == 0x0F6F:
            self.func = "mov"
            self.size = self.mm_or_xmm_operand_size()
            if self.prefix.repe:
                self.size = 16
            self.xmm_item_size = 1
            self.args.append(self.modrm().mm_or_xmm_register())
            self.args.append(self.modrm().mm_or_xmm_register_or_memory())
        elif self.opcode == 0x0F70:
            simd_prefix = self.prefix.simd_prefix
            if simd_prefix == 0x00:
                self.func = "pshuf"
                self.size = 8
                self.xmm_item_size = 2
            elif simd_prefix ==  0xF2: # Low bits
                self.func = "pshufl"
                self.size = 16
                self.xmm_item_size = 2
            elif simd_prefix == 0xF3: # High bits
                self.func = "pshufh"
                self.size = 16
                self.xmm_item_size = 2
            elif simd_prefix == 0x66:
                self.func = "pshuf"
                self.size = 16
                self.xmm_item_size = 4

            self.args.append(self.modrm().mm_or_xmm_register())
            self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            self.decode_immediate(1)
        elif self.opcode == 0x0F72:
            self.size = self.mm_or_xmm_operand_size()
            ext = self.modrm().opcode_ext()
            if ext in [2, 4]:
                raise "opcode extension not implemented"
            elif ext == 6:
                self.func = "psll"
                self.xmm_item_size = 4
                self.args.append(self.modrm().mm_or_xmm_register_or_memory())
                self.decode_immediate(1)
            else:
                self.unspecified_opcode_extension()
        elif self.opcode == 0x0F73:
            self.size = self.mm_or_xmm_operand_size()
            ext = self.modrm().opcode_ext()
            if ext == 2:
                raise "not implemented"
            elif ext == 6:
                self.func = "psll"
                self.xmm_item_size = 8
                self.args.append(self.modrm().mm_or_xmm_register_or_memory())
                self.decode_immediate(1)
            elif ext in [3, 7]:
                # TODO: verify that prefix 66 exists
                raise "not implemented"
            else:
                self.unspecified_opcode_extension()
        elif self.opcode == 0x0F7E:
            self.func = "movq"
            if not self.prefix.repe:
                raise "not implemented"
            self.size = 16  # It is a workaround. ModR/M uses size
                            # to distinguish  MMX and XMM registers
            self.args.append(self.modrm().mm_or_xmm_register())
            self.args[0].size = 8 # fix size
            self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            if self.modrm().mode() == 0x3:  # points to a register
                self.args[1].size = 16  # fix size
            else:
                self.args[1].size = 8   # fix size
        elif self.opcode == 0x0F7F:
            self.func = "mov"
            if self.prefix.operand_size_overridden or self.prefix.repe:
                self.size = 16
            else:
                self.size = 8
            self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            self.args.append(self.modrm().mm_or_xmm_register())
        elif self.opcode == 0x0FD6:
            if not self.prefix.operand_size_overridden:
                raise "not implemented"
            self.func = "movq"
            self.size = 8
            self.args.append(self.modrm().xmm_register_or_memory())
            self.args.append(self.modrm().xmm_register())
            if self.modrm().mode() == 0x3: # points to a register
                # to clear the highest bits of the XMM register
                self.args[1].size = 16
        elif self.opcode == 0x0FD7:
            self.func = "pmovmsk"
            self.size = 4
            self.args.append(self.modrm().register())
            size = self.mm_or_xmm_operand_size()
            self.modrm().operand_size = self.size
            self.args.append(self.modrm().mm_or_xmm_register_or_memory())
        elif self.opcode == 0x0FF0:
            if not self.prefix.repne:
                raise "F2 prefix expected"
            self.func = "mov"
            self.size = 16
            self.args.append(self.modrm().xmm_register())
            if self.modrm().mode() != 3:
                raise "register expected, but ModR/M mode is not 0b11" 
            self.args().append(self.modrm().xmm_register_or_memory())
        elif self.opcode >= 0x0F90 and self.opcode <= 0x0F9F:
            self.func = "set"
            self.size = 1
            self.args.append(self.modrm().register_or_memory())
            if self.condition_is_met(self.opcode % 16):
                self.encode_value(1)
            else:
                self.encode_value(0)
        else:
            if self.opcode in mm_xmm_reg_regmem_opcodes:
                arr = mm_xmm_reg_regmem_opcodes[self.opcode]
                self.func = arr[0]
                self.xmm_item_size = arr[1]
                self.size = mm_or_xmm_operand_size
                self.args.append(self.modrm().mm_or_xmm_register())
                self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            elif self.opcode in mm_xmm_reg_regmem_opcodes_signed:
                arr = mm_xmm_reg_regmem_opcodes_signed[self.opcode]
                self.func = arr[0]
                self.xmm_item_size = arr[1]
                self.size = self.mm_or_xmm_operand_size()
                self.args.append(self.modrm().mm_or_xmm_register())
                self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            elif self.opcode in unified_opcode_table:
                arr = unified_opcode_table[self.opcode]
                self.decode_arguments(arr)
            elif self.opcode in opcodes_with_extenstions:
                ext = self.modrm().opcode_ext()
                if ext in opcodes_with_extenstions[self.opcode]:
                    arr = opcodes_with_extenstions[self.opcode][ext]
                    self.decode_arguments(arr)
                else:
                    self.unspecified_opcode_extension()
            elif self.opcode in opcodes_with_simd_prefix:
                simd_prefix = self.prefix.simd_prefix
                if simd_prefix in opcodes_with_simd_prefix[self.opcode]:
                    arr = opcodes_with_simd_prefix[self.opcode][simd_prefix]
                    self.decode_arguments(arr)
                else:
                    raise "unspecified simd prefix"
            else:
                raise "not implemented: opcode 0x%x" % self.opcode

    def decode_arguments(self, arr):
        # size needs to be decoded first in case opcode extension is used
        # since modrm parsing relies on it

        size = arr[1]
        if size == BYTE:
            self.size = 1
        elif size == LONG:
            self.size = multi_byte()
        elif size == SIMD_16:
            self.size = 16

        self.func = arr[0]
        if self.func == "#ROTATE/SHIFT":
            self.func = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"][self.modrm().opcode_ext()]
        elif self.func == NOT_IMPLEMENTED:
            raise "not implemented"

        args = arr[2:]
        for arg in args:
            if arg == REG:
                self.args.append(self.modrm().register())
            elif arg == R_M:
                self.args.append(self.modrm().register_or_memory())
            elif arg == SIMD_REG:
                self.args.append(self.modrm().mm_or_xmm_register())
            elif arg == SIMD_REGMEM:
                self.args.append(self.modrm().mm_or_xmm_register_or_memory())
            elif arg == SIMD_ITEM_8:
                self.xmm_item_size = 8
            elif arg == ACC:
                self.encode_accumulator()
            elif arg == IM1:
                self.decode_immediate(1)
            elif arg == IMM:
                self.decode_immediate_16or32()
            elif arg == ZERO:
                self.encode_value(0)
            elif arg == ONE:
                self.encode_value(1)
            elif arg == C_F:
                self.encode_value(self.cpu.flags.c)
            else:
                raise "unknown argument: %s" % arg

    def mm_or_xmm_operand_size(self):
        if self.prefix.operand_size_overridden:
            return 16
        else:
            return 8

    def encode_regiser(self, reg):
        self.args.append(Pointer(self.cpu.register[reg], 0, self.size))

    def encode_accumulator(self):
        self.encode_regiser(0)

    def encode_counter(self):
        self.encode_regiser(1)

    def decode_register_from_opcode(self):
        reg = (self.opcode % 8) + 8 * self.prefix.rex_b
        self.encode_register(reg)        

    def decode_immediate(self, size=None):
        if size == None:
            size = self.size
        self.args.append(self.stream.read_signed_pointer(size))

    def decode_immediate_16or32(self):
        size = min(self.size, 4)
        self.decode_immediate(size)

    def encode_value(self.value, size=None):
        if self.size == None:
            size = 8
        elif size == None:
            size = self.size
        self.args.append(ConstBuffer(value, size).ptr())

    def decode_relative_address(self, size):
        rel = self.stream.read_pointer(size).read_signed()
        self.encode_value(self.cpu.rip + rel)

    def modrm(self):
        if self._modrm is None:
            self.parse_modrm()
        return self._modrm

    def parse_modrm(self):
        address_size = 8
        if self.prefix.address_size_overridden:
            address_size = 4

        self._modrm = ModRM_Parser(self.stream, self.prefix, self.cpu, self.size, address_size,
                                   self.segment_offset)

    def unspecified_opcode_extension(self):
        raise "Unspecified opcode extension %d for opcode 0x%X" % [self.modrm().opcode_ext(), self.opcode]

    def max_address(self):
        return 256 ** self.address_size

    def read_opcode(self, stream):
        byte1 = stream.read()
        if byte1 == 0x0F:
            byte2 = stream.read()
            if byte2 ==  0x38:
                byte3 = stream.read()
                return 0x0F3800 + byte3
            elif byte2 == 0x3A:
                byte3 = stream.read()
                return 0x0F3A00 + byte3
            else:
                return 0x0F00 + byte2
        else:
            return byte1

    def condition_is_met(self, cond=None):
        if code == None:
            cond = self.cond

        if cond == None:
            return True
        elif cond == 0:
            return self.cpu.flags.o
        elif cond == 1:
            return not self.cpu.flags.o
        elif cond == 2:
            return self.cpu.flags.c
        elif cond == 3:
            return not self.cpu.flags.c
        elif cond == 4:
            return self.cpu.flags.z
        elif cond == 5:
            return not self.cpu.flags.z
        elif cond == 6:
            return self.cpu.flags.c and self.cpu.flags.z
        elif cond == 7:
            return not self.cpu.flags.c and not self.cpu.flags.z
        elif cond == 8:
            return self.cpu.flags.s
        elif cond == 9:
            return not self.cpu.flags.s
        elif cond == 10:
            return self.cpu.flags.p
        elif cond == 11:
            return not self.cpu.flags.p
        elif cond == 12:
            return self.cpu.flags.s != self.cpu.flags.o
        elif cond == 13:
            return self.cpu.flags.s == self.cpu.flags.o
        elif cond == 14:
            return self.cpu.flags.z and self.cpu.flags.s != self.cpu.flags.o
        elif cond == 15:
            return not self.cpu.flags.z and self.cpu.flags.s == self.cpu.flags.o
        else:
            raise "unexpected value of `cond`: %d" % cond

    def segment_offset(self):
        if self.prefix.segment == "FS":
            return self.cpu.fs * 16 
        if self.prefix.segment == "GS":
            return self.cpu.gs * 16 
        if self.prefix.segment == "none":
            return 0
        raise "unexpected name of the segment: " + self.prefix.segment

    def execute(self):
        print("opcode: %x" % self.opcode)
        print(self.func)
        if self.cond == None:
            print("condition: none")
        else:
            print("condition: %d" % self.cond)
        for arg in self.args:
            print("arg = %s pos=%x size=%d ==> %s" % [arg.mem.name, arg.pos, arg.size, arg.debug_value])

        if not self.condition_is_met():
            return

        args = self.args
        func = self.func

        if func in ["ins", "movs", "outs", "lods", "stos", "cmps", "scas"]:
            return self.execute_string_instruction()
        elif func ==  "lea":
            if self.modrm().mode() == 0x03:
                raise "LEA & register-direct addressing mode"
            args[0].write_int(args[1].pos)
        elif func in ["mov", "set", "movap"]:
            args[0].write(args[1].read())
        elif func == "movq": # used in moving data from the lowest bits of XMM to XMM/memory
            args[0].write_with_zero_extension(args[1].read())
        elif func in ["movsxd", "movsx"]:
            args[0].write_int(args[1].read_signed())
        elif func == "movzx":
            args[0].write_int(args[1].read_int())
        elif func == "xchg":
            tmp = args[1].read()
            args[1].write(args[0].read())
            args[0].write(tmp)
        elif func == "pop":
            args[0].write(self.cpu.stack.pop(self.size))
        elif func == "push":
            self.cpu.stack.push(args[0].read())
        elif func == "call":
            raise "not converted from ruby"
            # @cpu.stack.push [@cpu.rip].pack("Q<").unpack("C*")
            # @cpu.rip = @args[0].read_int
        elif func == "retn":
            raise "not converted from ruby"
            # @cpu.rip = @cpu.stack.pop(8).pack("C*").unpack("Q<")[0]
            # @cpu.stack.pop(@args[0].read_int)
        elif func == "syscall":
            raise "not converted from ruby"
            # syscall_number = @cpu.register[0].read(0, 8).pack("C*").unpack("Q<")[0]
            # @linux.handle_syscall(syscall_number, [
            #    @cpu.register[7].read(0, 8).pack("C*").unpack("Q<")[0],
            #    @cpu.register[6].read(0, 8).pack("C*").unpack("Q<")[0],
            #    @cpu.register[2].read(0, 8).pack("C*").unpack("Q<")[0],
            #    @cpu.register[10].read(0, 8).pack("C*").unpack("Q<")[0],
            #    @cpu.register[8].read(0, 8).pack("C*").unpack("Q<")[0],
            #    @cpu.register[9].read(0, 8).pack("C*").unpack("Q<")[0],
            #])
        elif func == 'xor':
            value = args[0].read_int() ^ args[1].read_int()
            args[0].write_int(value)
            self.update_szp_flags(value, args[0].size)
            self.cpu.flags.o = 0
            self.cpu.flags.c = 0
        elif func == 'or':
            value = args[0].read_int() | args[1].read_int()
            args[0].write_int(value)
            self.update_szp_flags(value, args[0].size)
            self.cpu.flags.o = 0
            self.cpu.flags.c = 0
        elif func in ['and', 'test']:
            value = args[0].read_int() & args[1].read_int()
            if func == 'and':
                args[0].write_int(value)
            self.update_szp_flags(value, args[0].size)
            self.cpu.flags.o = 0
            self.cpu.flags.c = 0
        elif func in ['add', 'adc', 'inc']:
            highest_bit1 = Utils.highest_bit(args[0].read_int(), args[0].size)
            highest_bit2 = Utils.highest_bit(args[1].read_int(), args[1].size)

            cf = 0
            if (func == 'adc') and self.cpu.flags.c:
                cf = 1

            value = args[0].read_int() + args[1].read_signed() + cf
            args[0].write_int(value)

            if func != 'inc':
                self.cpu.flags.c = value >= 2 ** (8 * args[0].size)

            highest_res = Utils.highest_bit(args[0].read_int(), args[0].size)

            self.cpu.flags.o = (highest_res and not highest_bit1 and not highest_bit2) or \
                (not highest_res and highest_bit1 and highest_bit2)

            self.update_szp_flags(value, args[0].size)
        elif func in ['sub', 'sbb', 'cmp', 'dec', 'neg']:
            highest_bit1 = Utils.highest_bit(args[0].read_int(), args[0].size)
            highest_bit2 = Utils.highest_bit(args[1].read_int(), args[1].size)

            cf = 0
            if func == 'sbb':
                cf = self.cpu.flags.c
            value = args[0].read_int() - args[1].read_signed() - cf

            dest_idx = 0
            if func == 'neg':
                dest_idx = 1

            if func != 'cmp':
                args[dest_idx].write_int(value)

            self.update_szp_flags(value, args[0].size)

            if func != 'dec':
                self.cpu.flags.c = value < 0

            highest_res = value[2 ** (8 * self.size - 1)] == 1
            self.cpu.flags.o = (not highest_bit1 and highest_bit2 and highest_res) or \
                               (highest_bit1 and not highest_bit2 and not highest_res)
        elif func == 'xadd':
            self.func = 'xchg'
            self.execute()
            self.func = 'add'
            self.execute()
        elif func == 'div':
            if self.size == 1:
                raise "div not implemented for size = 1"
            rax = Pointer(self.cpu.register[0], 0, self.size)
            rdx = Pointer(self.cpu.register[2], 0, self.size)
            dividend = (256 ** self.size) * rdx.read_int() + rax.read_int()
            divisor = args[0].read_int()
            if divisor == 0:
                raise "divide error exception: divisor = 0"

            quotient = dividend / divisor
            remainder = dividend % divisor
            if quotient >= 256 ** self.size:
                raise "divide error exception: quotient too big: %d (dec) / %x (hex)" % [quotient, quotient]

            rax.write_int(quotient)
            rdx.write_int(remainder)
        elif func == 'imul':
            if len(args) == 1:
                raise "not implemented"
            elif len(args) == 2:
                args = [args[0]] + args
            elif len(args) == 3:
                pass

            value = args[1].read_signed() * args[2].read_signed()
            args[0].write_int(value)

            size = self.size
            self.cpu.flags.c = (value < -(2**(8*size-1)) or (value >= 2**(8*size-1)))
            self.cpu.flags.o = self.cpu.flags.c
        elif func == 'bsf':
            self.cpu.flags.z = args[1].read_int() == 0
            if not self.cpu.flags.z:
                args[0].write_int(args[1].read_bit_array()[1])
        elif func == 'bsr':
            self.cpu.flags.z = args[1].read_int() == 0
            if not self.cpu.flags.z:
                args[0].write_int(args[1].read_bit_array()[-1])
        if func in ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]:
            times = args[1].read_int() % (2 ** self.size)
            bit_array = args[0].read_bit_array()
            for i in range(times):
                if func == "rol":
                    highest_bit = args[0].highest_bit()
                    args[0].write_int(args[0].read_int() * 2 + highest_bit)
                    self.cpu.flags.c = highest_bit == 1
                    self.cpu.flags.o = self.cpu.flags.c ^ (args[0].highest_bit == 1)
                elif func == "ror":
                    orig_highest_bit = args[0].highest_bit()
                    value = args[0].read_int()
                    self.cpu.flags.c = value & 1
                    args[0].write_int(value / 2)
                    self.cpu.flags.o = orig_highest_bit == 1
                elif func == "rcl":
                    bit_array.shift(self.cpu.flags.c)
                    self.cpu.flags.c = bit_array.pop() == 1
                    self.cpu.flags.o = self.cpu.flags.c ^ (bit_array[-1] == 1)
                    args[0].write_bit_array(bit_array)
                elif func == "rcr":
                    bit_array.push(self.cpu.flags.c)
                    self.cpu.flags.c = bit_array.unshift() == 1
                    self.cpu.flags.o = bit_array[-1] != bit_array[-2]
                    args[0].write_bit_array(bit_array)
                elif func in ["shr", "sar"]:
                    orig_highest_bit = bit_array[-1]
                    if func == "shr":
                        bit_array.push(0)
                    else:
                        bit_array.push(bit_array[-1])
                    self.cpu.flags.c = bit_array.shift == 1
                    if times == 1:
                        self.cpu.flags.o = (func == "shr") and orig_highest_bit
                    args[0].write_bit_array(bit_array)
                if func in  ["shl", "sal"]:
                    bit_array.unshift(0)
                    self.cpu.flags.c = bit_array.pop == 1
                    if times == 1:
                        self.cpu.flags.o = self.cpu.flags.c != (bit_array[-1] == 1)
                    args[0].write_bit_array(bit_array)
        elif func == 'jmp':
            self.jump(args[0])
        elif func in ['loop', 'loopz', 'loopnz']:
            rcx = self.args[0]
            rcx.write_int(rcx.read_int() - 1)
            if rcx.read_int == 0:
                return

            will_jump = False
            if func == "loop":
                will_jump = True
            elif func == "loopz" and self.cpu.flags.z:
                will_jump = True
            elif func == "loopnz" and not self.cpu.flags.z:
                will_jump = True

            if will_jump:
                self.jump(args[1])

        elif func == 'sahf':
            ah = self.cpu.register[0].read(1, 1)[0]
            self.cpu.flags.c = ah[0] == 1
            self.cpu.flags.p = ah[2] == 1
            self.cpu.flags.a = ah[4] == 1
            self.cpu.flags.z = ah[6] == 1
            self.cpu.flags.s = ah[7] == 1
        elif func == 'lahf':
            ah = 0
            ah += self.cpu.flags.c
            ah += 2
            ah += self.cpu.flags.p * 4
            ah += self.cpu.flags.a * 16
            ah += self.cpu.flags.z * 64
            ah += self.cpu.flags.s * 128
            self.cpu.register[0].write(1, [ah])
        elif func == 'cpuid':
            # Do nothing
            pass
        elif func == 'cmc': # Complement Carry Flag
            self.cpu.flags.c = not self.cpu.flags.c
        elif func == 'clc': # Clear Carry Flag
            self.cpu.flags.c = False
        elif func == 'stc': # Set Carry Flag
            self.cpu.flags.c = True
        elif func == 'cld': # Clear Direction Flag
            self.cpu.flags.d = False
        elif func == 'std': # Set Direction Flag
            self.cpu.flags.d = True
        elif func in ['nop', 'pause', "hint_nop"]:
            # do nothing
            pass
        elif func == "pcmpeq":
            self.for_each_xmm_item(lambda dest, arg: -1 if dest == arg else 0)
        elif func == "pxor":
            self.for_each_xmm_item(lambda dest, arg: dest ^ arg)
        elif func == "pand":
            self.for_each_xmm_item(lambda dest, arg: dest & arg)
        elif func == "pandn":
            self.for_each_xmm_item(lambda dest, arg: (~dest) & arg)
        elif func == "por":
            self.for_each_xmm_item(lambda dest, arg: dest | arg)
        elif func == "padd":
            self.for_each_xmm_item(lambda dest, arg: dest + arg)
        elif func == "psub":
            self.for_each_xmm_item(lambda dest, arg: dest - arg)
        elif func == "psubus":
            self.for_each_xmm_item(lambda dest, arg: max(dest - arg, 0))
        elif func == "paddus":
            self.for_each_xmm_item(lambda dest, arg: min(dest + arg, 256 ** self.xmm_item_size - 1))
        elif func == "pminu":
            self.for_each_xmm_item(lambda dest, arg: [dest, arg].min)
        elif func == "pmaxu":
            self.for_each_xmm_item(lambda dest, arg: [dest, arg].max)
        elif func == "pavg":
            self.for_each_xmm_item(lambda dest, arg: (dest + arg + 1) >> 1)
        elif func == "pcmpgt":
            self.for_each_xmm_item_signed(lambda dest, arg: -1 if dest > arg else 0)
        elif func == "psll":
            self.for_each_xmm_item_and_constant(lambda dest, arg: dest << arg)
        elif func == "psll":
            self.for_each_xmm_item_and_constant(lambda dest, arg: dest << arg)
        if func in ["punpckl", "punpckh"]:
            arr = []
            for i in range(self.size / self.xmm_item_size):
                dest = Pointer.new(self.args[0].mem, self.args[0].pos + i * self.xmm_item_size, self.xmm_item_size)
                arg2 = Pointer.new(self.args[1].mem, self.args[1].pos + i * self.xmm_item_size, self.xmm_item_size)
                arr.append(dest.read())
                arr.append(arg2.read())

            if func == "punpckl":
                arr = arr[:self.size]
            else:
                arr = arr[self.size:2*self.size]

            args[0].write(arr)
        elif func == "pmovmsk":
            args[0].write_with_zero_extension([])
            arr = [Utils.highest_bit(x) for x in args[1].read()]
            args[0].write_bit_array(arr)
        elif func == "pshuf":
            order = args[2].read_int()
            data = args[1].read() + [0] * (self.xmm_item_size * 3)
            for i in range(self.size / self.xmm_item_size):
                dest = Pointer(args[0].mem, args[0].pos + i * self.xmm_item_size, self.xmm_item_size)
                shift = (order >> (2*i)) & 0b11
                dest.write(data[self.xmm_item_size * (i + shift): self.xmm_item_size * (i + 1 + shift)])
        elif func == "pshufl":
            self.func = "pshuf"
            self.execute()
            args[0].pointer_to_upper_half().write(args[1].pointer_to_upper_half().read())
        elif func == "pshufh":
            self.func = "pshuf"
            self.execute()
            args[0].pointer_to_lower_half().write(args[1].pointer_to_lower_half().read())
        else:
            raise "function not implemented: " + self.func

    def for_each_xmm_item(self, func):
        args = self.args
        for i in range(self.size / self.xmm_item_size):
            dest_ptr = Pointer(args[0].mem, args[0].pos + i * self.xmm_item_size, self.xmm_item_size)
            arg_ptr  = Pointer(args[1].mem, args[1].pos + i * self.xmm_item_size, self.xmm_item_size)
            dest = dest_ptr.read_int()
            arg = arg_ptr.read_int()
            dest_ptr.write_int(func(dest, arg))

    def for_each_xmm_item_signed(self, func):
        args = self.args
        for i in range(self.size / self.xmm_item_size):
            dest_ptr = Pointer(args[0].mem, args[0].pos + i * self.xmm_item_size, self.xmm_item_size)
            arg_ptr  = Pointer(args[1].mem, args[1].pos + i * self.xmm_item_size, self.xmm_item_size)
            dest = dest_ptr.read_int()
            arg = arg_ptr.read_int()
            dest_ptr.write_int(func(dest, arg))

    def for_each_xmm_item_and_constant(self, func):
        args = self.args
        arg = args[1].read_int()
        for i in range(self.size / self.xmm_item_size):
            dest_ptr = Pointer(args[0].mem, args[0].pos + i * self.xmm_item_size, self.xmm_item_size)
            dest = dest_ptr.read_int()
            dest_ptr.write_int(func(dest, arg))

    def execute_string_instruction(self):
        string_func = self.func

        loop_mode = "none"
        if self.prefix.repe:
            if string_func in ["cmps", "scas"]:
                loop_mode = "repe"
            else:
                loop_mode = "rep"
        elif self.prefix.repne:
            loop_mode = "repne"

        while True:
            rax = Pointer(self.cpu.register[0], 0, self.size)
            rcx = Pointer(self.cpu.register[1], 0, self.size)
            rsi = Pointer(self.cpu.register[6], 0, self.address_size)
            rdi = Pointer(self.cpu.register[7], 0, self.address_size)

            # ES:EDI, DS:ESI. Only DS can be overridden.
            pointed_by_rdi = Pointer(self.stream.mem,
                                     rdi.read_int() % self.max_address(), self.size)
            pointed_by_rsi = Pointer(self.stream.mem,
                                     (self.segment_offset() + rsi.read_int()) % self.max_address(),
                                     self.size)

            ptr_diff = -self.size if self.cpu.flags.d else self.size

            if string_func == "cmps":
                self.func = "cmp"
                self.args = [pointed_by_rdi, pointed_by_rsi]
                self.execute()
                rdi.write_int(rdi.read_int() + ptr_diff)
                rsi.write_int(rsi.read_int() + ptr_diff)
            elif string_func == "movs":
                pointed_by_rdi.write(pointed_by_rsi.read())
                rdi.write_int(rdi.read_int() + ptr_diff)
                rsi.write_int(rsi.read_int() + ptr_diff)
            elif string_func == "lods":
                rax.write(pointed_by_rsi.read())
                rsi.write_int(rsi.read_int() + ptr_diff)
            elif string_func == "stos":
                pointed_by_rdi.write(rax.read())
                rdi.write_int(rdi.read_int() + ptr_diff)
            elif string_func == "scas":
                self.func = "cmp"
                self.args = [rax, pointed_by_rdi]
                self.execute()
                rdi.write_int(rdi.read_int() + ptr_diff)
            else:
                raise "string function not implemented: " + string_func

            # TODO: is RCX changed if there is no rep* prefix?
            if loop_mode != "none":
                rcx.write_int(rcx.read_int() - 1)

            rcx_empty = rcx.read_int == 0

            if loop_mode == "none":
                break
            elif (loop_mode == "rep") and rcx_empty:
                break
            elif (loop_mode == "repe") and (rcx_empty or not self.cpu.flags.z):
                break
            elif (loop_mode == "repne") and (rcx_empty or not self.cpu.flags.z):
                break
            else:
                raise "bad loop_mode: %s" % loop_mode

    def update_szp_flags(self, value, size):
        # sign flag
        self.cpu.flags.s = Utils.highest_bit(value, size)
        # zero flag
        self.cpu.flags.z = value == 0
        # parity flag
        self.cpu.flags.p = value & 1 == 0

    # calculate operand size if operand size is not 1 ("multi-byte")
    def multi_byte(self):
        if self.prefix.rex_w == 1:
            return 8
        elif self.prefix.operand_size_overridden:
            return 2
        else:
            return 4

    def jump(self, pos):
        self.cpu.rip = pos.read_int()

    mm_xmm_reg_regmem_opcodes = {
        # format: opcode: [operation, item size]
        0x0F60: ['punpckl', 1],
        0x0F61: ['punpckl', 2],
        0x0F62: ['punpckl', 4],
        0x0F68: ['punpckh', 1],
        0x0F69: ['punpckh', 2],
        0x0F6A: ['punpckh', 4],
        0x0F74: ['pcmpeq', 1],
        0x0F75: ['pcmpeq', 2],
        0x0F76: ['pcmpeq', 4],
        0x0FD4: ['padd', 8],
        0x0FD8: ['psubus', 1],
        0x0FD9: ['psubus', 2],
        0x0FDA: ['pminu', 1],
        0x0FDB: ['pand', 8],
        0x0FDC: ['paddus', 1],
        0x0FDD: ['paddus', 2],
        0x0FDE: ['pmaxu', 1],
        0x0FDF: ['pandn', 1],
        0x0FE0: ['pavg', 1],
        0x0FE3: ['pavg', 2],
        0x0FEB: ['por', 8],
        0x0FEF: ['pxor', 8],
        0x0FF8: ['psub', 1],
        0x0FF9: ['psub', 2],
        0x0FFA: ['psub', 4],
        0x0FFB: ['psub', 8],
        0x0FFC: ['padd', 1],
        0x0FFD: ['padd', 2],
        0x0FFE: ['padd', 4],
    }

    mm_xmm_reg_regmem_opcodes_signed = {
        # format: opcode: [operation, item size]
        0x0F64: ['pcmpgt', 1],
        0x0F65: ['pcmpgt', 2],
        0x0F66: ['pcmpgt', 4],
    }

    # operation size
    BYTE = "s=1"       # 1 byte
    LONG = "s=2/4/8"   # 2/4/8 bytes
    SIMD_16 = "simd16" # 16 bytes, XMM

    SIMD_ITEM_8 = "simd item size = 8"

    # arguments
    REG = "r"    # register
    R_M = "r/m"  # register / memory
    IMM = "imm"  # immediate value not longer than 4 bytes
    IM1 = "imm1" # 1-byte immediate value
    ACC = "acc"  # accumulator
    ZERO = "_0_" # constant value of 0
    ONE = "_1_"  # constant value of 1
    C_F = "c_f"  # carry flag
    SIMD_REG = "simd_reg" # MM/XMM ModR/M register
    SIMD_REGMEM = "simd_remem" # MM/XMM ModR/M register or memory

    NOT_IMPLEMENTED = "n/i" # opcode or opcode extension not implemented

    unified_opcode_table = {
        0x69: ["imul", LONG, REG, R_M, IMM],
        0x6B: ["imul", LONG, REG, R_M, IM1],
        0x84: ['test', BYTE, R_M, REG],
        0x85: ['test', LONG, R_M, REG],
        0x86: ['xchg', BYTE, REG, R_M],
        0x87: ['xchg', LONG, REG, R_M],
        0x88: ['mov',  BYTE, R_M, REG],
        0x89: ['mov',  LONG, R_M, REG],
        0x8A: ['mov',  BYTE, REG, R_M],
        0x8B: ['mov',  LONG, REG, R_M],
        0x8D: ['lea',  LONG, REG, R_M],
        0x9E: ["sahf"],
        0x9F: ["lahf"],
        0xA4: ["movs", BYTE],
        0xA5: ["movs", LONG],
        0xA6: ["cmps", BYTE],
        0xA7: ["cmps", LONG],
        0xA8: ["test", BYTE, ACC, IM1],
        0xA9: ["test", LONG, ACC, IMM],
        0xAA: ["stos", BYTE],
        0xAB: ["stos", LONG],
        0xAC: ["lods", BYTE],
        0xAD: ["lods", LONG],
        0xAE: ["scas", BYTE],
        0xAF: ["scas", LONG],
        0xC0: ["#ROTATE/SHIFT", BYTE, R_M, IM1],
        0xC1: ["#ROTATE/SHIFT", LONG, R_M, IM1],
        0xD0: ["#ROTATE/SHIFT", BYTE, R_M, ONE],
        0xD1: ["#ROTATE/SHIFT", LONG, R_M, ONE],
        0xD2: ["#ROTATE/SHIFT", BYTE, R_M, C_F],
        0xD3: ["#ROTATE/SHIFT", LONG, R_M, C_F],
        0xF5: ['cmc'],
        0xF8: ['clc'],
        0xF9: ['stc'],
        0xFA: ['cli'],
        0xFB: ['sti'],
        0xFC: ['cld'],
        0xFD: ['std'],
        0x0F05: ["syscall"],
        0x0FA2: ['cpuid'],
        0x0FAF: ['imul', LONG, REG, R_M],
        0x0FBC: ['bsf',  LONG, REG, R_M],
        0x0FBD: ['bsr',  LONG, REG, R_M],
        0x0FC0: ['xadd', BYTE, R_M, REG],
        0x0FC1: ['xadd', LONG, R_M, REG],
    }

    opcodes_with_extenstions = {
        0xC6: {0: ["mov", BYTE, R_M, IMM]},
        0xC7: {0: ["mov", LONG, R_M, IMM]},
        0xFE: {
            0: ["inc", BYTE, R_M, ONE],
            1: ["dec", BYTE, R_M, ONE],
        },
        0xF6: {
            0: ["test", BYTE, R_M, IMM],
            1: ["test", BYTE, R_M, IMM],
            2: [NOT_IMPLEMENTED],
            3: ["neg", BYTE, ZERO, R_M],
            4: [NOT_IMPLEMENTED],
            5: [NOT_IMPLEMENTED],
            6: [NOT_IMPLEMENTED],
            7: [NOT_IMPLEMENTED],
        },
        0xF6: {
            0: ["test", LONG, R_M, IMM],
            1: ["test", LONG, R_M, IMM],
            2: [NOT_IMPLEMENTED],
            3: ["neg", LONG, ZERO, R_M],
            4: [NOT_IMPLEMENTED],
            5: [NOT_IMPLEMENTED],
            6: ["div", LONG, R_M],
            7: [NOT_IMPLEMENTED],
        }
    }

    opcodes_with_simd_prefix = {
        0x0F10: {
            0x00: ["mov", SIMD_16, SIMD_REG, SIMD_REGMEM],
            0xF3: [NOT_IMPLEMENTED],
            0x66: [NOT_IMPLEMENTED],
            0xF2: [NOT_IMPLEMENTED],
        },
        0x0F11: {
            0x00: ["mov", SIMD_16, SIMD_REGMEM, SIMD_REG],
            0xF3: [NOT_IMPLEMENTED],
            0x66: [NOT_IMPLEMENTED],
            0xF2: [NOT_IMPLEMENTED],
        },
        0x0F28: {
            0x00: ["movap", SIMD_16, SIMD_REG, SIMD_REGMEM],
            0x66: ["movap", SIMD_16, SIMD_REG, SIMD_REGMEM],
        },
        0x0F29: {
            0x00: ["movap", SIMD_16, SIMD_REGMEM, SIMD_REG],
            0x66: ["movap", SIMD_16, SIMD_REGMEM, SIMD_REG],
        },
        0x0F6C: { 0x66: ["punpckl", SIMD_16, SIMD_ITEM_8, SIMD_REG, SIMD_REGMEM]},
        0x0F6D: { 0x66: ["punpckh", SIMD_16, SIMD_ITEM_8, SIMD_REG, SIMD_REGMEM]},
    }

class ModRM_Parser:
    def __init__(self, stream, prefix, cpu, operand_size, address_size,\
                 segment_offset):
        self.prefix = prefix
        self.stream = stream
        self.modrm = stream.read
        self.cpu = cpu
        self.operand_size = operand_size
        self.address_size = address_size
        self.segment_offset = segment_offset

    def mode(self):
        return (self.modrm >> 6) & 0x3

    def opcode_ext(self):
        return (self.modrm & 0x38) >> 3

    def register(self):
        index = ((self.modrm & 0x38) >> 3) + self.prefix.reg_extension
        return Pointer(self.cpu.register[index], 0, self.operand_size)

    def mm_or_xmm_register(self):
        index = ((self.modrm & 0x38) >> 3) + self.prefix.reg_extension
        if self.operand_size == 8:
            return Pointer(self.cpu.mm_register[index], 0, self.operand_size)
        else:
            return Pointer(self.cpu.xmm_register[index], 0, self.operand_size)

    def xmm_register(self):
        index = ((self.modrm & 0x38) >> 3) + self.prefix.reg_extension
        return Pointer(self.cpu.xmm_register[index], 0, self.operand_size)

    def register_or_memory(self):
        regmem = (self.modrm & 0x07) + 8 * self.prefix.rex_b

        mode = self.mode()

        if mode == 0x03:
            return Pointer(self.cpu.register[regmem], 0, self.operand_size)
        else:
            if regmem in [0x4, 0xC]:
                return self.sib()
            elif (regmem in [0x5, 0xD]) and (mode == 0):
                rel = self.stream.read_pointer(4).read_signed()
                return self.memory_at(self.cpu.rip + rel)
            else:
                addr = self.cpu.register[regmem].read_int(0, self.address_size)

                if mode == 0x1:
                    addr += self.disp8()
                elif mode == 0x2:
                    addr += self.disp32()

                return self.memory_at(addr)

    def mm_or_xmm_register_or_memory(self):
        regmem = (self.modrm & 0x07) + 8 * self.prefix.rex_b

        op_size = self.operand_size

        if self.mode() == 0x03:
            if op_size == 8:
                return Pointer(self.cpu.mm_register[regmem], 0, op_size)
            else:
                return Pointer(self.cpu.xmm_register[regmem], 0, op_size)
        else:
            # TODO: is pointer to memory stored in a general purpose register
            # or in MM/XMM register?
            return self.register_or_memory()

    def xmm_register_or_memory(self):
        regmem = (self.modrm & 0x07) + 8 * self.prefix.rex_b
        if self.mode() == 0x03:
            return Pointer(self.cpu.xmm_register[regmem], 0, self.operand_size)
        else:
            # TODO: is pointer to memory stored in a general purpose register
            # or in MM/XMM register?
            return self.register_or_memory()

    def memory_at(self, pos):
        print("memory_at %x" % pos)
        # TODO: shall @segment_offset be used in all cases
        # TODO: how do segment overrides work with RIP addressing
        max_addr = 256 ** self.address_size
        return Pointer(self.stream.mem,
                       (self.segment_offset + pos) % max_addr,
                       self.operand_size)

    def disp32(self):
        return self.stream.read_pointer(4).read_signed()

    def disp8(self):
        return self.stream.read_pointer(1).read_signed()

    def sib(self):
        sib = self.stream.read()
        scale = 2 ** (sib >> 6)
        index_reg = ((sib >> 3) & 0x07) + 8 * self.prefix.rex_x
        base_reg = (sib & 0x07) + 8 * self.prefix.rex_b

        index = None
        if index_reg == 4:
            index = 0
        else:
            index = self.cpu.register[index_reg].read_int(0, self.address_size)

        base = self.cpu.register[base_reg].read_int(0, self.address_size)

        mode = self.mode()
        if mode == 0x0:
            if base_reg in [0x5, 0xD]:
                return self.memory_at(index * scale + self.disp32())
            else:
                return self.memory_at(base + index * scale)
        elif mode == 0x1:
            return self.memory_at(base + index * scale + self.disp8())
        elif mode == 0x2:
            return self.memory_at(base + index * scale + self.disp32())
