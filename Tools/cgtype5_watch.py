import lldb

ALLOCATION_RETURN = 0x183D7487C
ALLOCATION_SIZE = 0xD9B0
EXPECTED_RANGE = 6


def read_u64(process, address):
    error = lldb.SBError()
    data = process.ReadMemory(address, 8, error)
    if error.Fail():
        raise RuntimeError(error.GetCString())
    return int.from_bytes(data, "little")


def cgtype5_allocation(frame, breakpoint_location, dictionary):
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    buffer_address = frame.FindRegister("x0").GetValueAsUnsigned()
    if not buffer_address:
        return True
    shading = frame.FindRegister("x20").GetValueAsUnsigned()
    function = read_u64(process, shading + 0x58)
    range_dimension = read_u64(process, function + 0x30)
    if range_dimension != EXPECTED_RANGE:
        return True
    error = lldb.SBError()
    watch = target.WatchAddress(buffer_address + ALLOCATION_SIZE, 8, False, True, error)
    if error.Fail() or not watch.IsValid():
        raise RuntimeError(error.GetCString() or "failed to install Type 5 watchpoint")
    print(f"TYPE5_WATCH_READY B=0x{buffer_address:x} R={range_dimension} watch=0x{buffer_address + ALLOCATION_SIZE:x}")
    print(f"After the write stop, inspect: memory read -s 8 -c 2 -f x 0x{buffer_address + ALLOCATION_SIZE - 8:x}")
    return True


target = lldb.debugger.GetSelectedTarget()
module = next((item for item in target.module_iter() if item.file.basename == "CoreGraphics"), None)
if module is None:
    raise RuntimeError("CoreGraphics is not loaded")
header = module.GetObjectFileHeaderAddress()
slide = header.GetLoadAddress(target) - header.GetFileAddress()
breakpoint = target.BreakpointCreateByAddress(slide + ALLOCATION_RETURN)
breakpoint.SetScriptCallbackFunction("cgtype5_allocation")
print(f"TYPE5_BREAKPOINT slide=0x{slide:x} allocation_return=0x{slide + ALLOCATION_RETURN:x}")
target.GetProcess().Continue()
