import idaapi, idc, idautils


class DecryptorError(Exception):
    pass


def rc4crypt(key, data):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    return ''.join(out)


def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts()


def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(address, text)


def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    ## Just for safety only count back 500 heads
    while e_count < 500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                        return idc.get_operand_value(ptr_addr, 1)
        elif idc.print_insn_mnem(ptr_addr) == 'pop':
            ## Match the following pattern
            ## push    3
            ## pop     edi
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    ## Get prev command
                    tmp_addr = idc.prev_head(ptr_addr)
                    if idc.print_insn_mnem(tmp_addr) == 'push':
                        if idc.get_operand_type(tmp_addr, 0) == idc.o_imm:
                            reg_value = idc.get_operand_value(tmp_addr, 0)
                            return reg_value
        elif idc.print_insn_mnem(ptr_addr) == 'ret':
            ## We ran out of space in the function
            raise DecryptorError()
    ## If we got here we hit the e_count
    raise DecryptorError()


def get_stack_args(fn_addr, count):
    args = []
    arg_count = 0
    ptr_addr = fn_addr
    while arg_count < count:
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'push':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_imm:
                args.append(idc.get_operand_value(ptr_addr, 0))
                arg_count += 1
            elif idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                reg_value = get_reg_value(ptr_addr, reg_name)
                args.append(reg_value)
                arg_count += 1
            else:
                ## We can't handle pushing reg values so throw error
                raise DecryptorError()
    return tuple(args)


def get_xref_list(fn_addr):
    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]



def decrypt_string(fn_address):
    try:
        str_tbl_start, offset, key_len, str_len = get_stack_args(fn_address, 4)
    except:
        print "Can't get args"
        return
    key_data = idc.get_bytes(str_tbl_start + offset, key_len)
    str_data = idc.get_bytes(str_tbl_start + offset + key_len, str_len)
    plaintxt_str =  rc4crypt(key_data, str_data)
    out_str = plaintxt_str.replace('\x00','')
    print "0x%x:    %s" % (fn_address, out_str)
    set_comment(fn_address, out_str)


def decrypt_all_strings(fn_address):
    for ptr in get_xref_list(fn_address):
        decrypt_string(ptr)
