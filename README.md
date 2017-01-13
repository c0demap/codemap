# CODEMAP

## Introduction

Codemap is a binary analysis tool for "run-trace visualization" provided as IDA plugin.

Unlike DBI(Dynamic Binary Instrumentation) based tools such as Intel PIN or QEMU, 
Codemap uses 'tracepoints' for generating the register/memory information while 
the program's control flow passes the tracepoint.

If the program hits a tracepoint, Codemap call-back handler is invoked
then proper action for trace is taken; and program continues.  
This might sound like a slow/inefficient approach for execution tracing.
However, there are two major advantages by tracing the binary in this manner.

### 1. Selective Tracing

When you trace a binary with Codemap, you can "selectively set break-points only against instructions of your interest".

These selective break-points avoid unneccessary tracing against meaningless part (out of your interest) of program.
In most of case when you reverse-engineer a software, you want to analyze a very specific portion of the binary.
For example, if you are analyzing a reason of program crash, you probably want to
extract the execution log around that particular crashing point only.
The "selective tracing" capability of Codemap perfectly suits for such cases.


### 2. Semantic Tracing

Note that 'program execution trace' is not only thing that Codemap can trace. 
In fact, Codemap can trace entire register context. 
This enables Codemap to generate very concrete and flexible trace results. 
We refer this feature as 'Semantic Tracing'

For example, to trace the "size of allocated heap chunks", you can set a break-point against an instruction which references
a register that contains the size of heap chunk.  Likely candidate would be an instruction from the starting part of malloc().

For another example, to trace the entire "heap chunk address", you can set a break-point at the end of malloc()
and trace the EAX register value(always holds the chunk location at that moment) to visualize the overall location of heap chunks.

As long as you understand the 'semantic of register context' while specific instruction is being executed
you can effectivly trace/visualize these semantics, which can be very helpful to understand the behaviour of binary.
you can also make your own SQL statement and specify how to visualize these results.


## Requirements (essential)
- IDA Pro 6.5 or after. (6.6 is recommended, don't use cracked version, Codemap might not work)
- Python 2.x

## Requirements (recommended)
- Chrome web browser
- Large screen / Dual monitor environment

## How to install
- run `python install.py` from Codemap home directory

## How to use
Basically, codemap hooks IDA and place its own break-point event handler.
every time when a program hits break-point, codemap will save register/memory information of that moment into DB.
Later, codemap visualizes this trace information in the web-browser with SQL query.

There are 5 commands for Codemap.

### ALT-1 : Start/Pause Codemap

This button starts the Codemap tracing.  
before you press this button, make sure setup break-points where you wan to trace the binary.
if you press this button again, Codemap will pause. to resume, press the button again.
You must pause the Codemap to see accurate result. If you don't pause, 
some trace information can be buffered and not showed in browser screen.

### ALT-2 : Set Function BP

This button set break-points against entire instruction inside the function that you currently put cursor.
note that, the function (pointed by your cursor) should be recognized by IDA.
- in order to force IDA to disassemble the byte stream, put the cursor on the byte that you think as the
starting point of instructions, then press 'C' button.
- in order to force IDA to recognize a function, put the cursor on the instruction that you think as the 
starting point of function, then press 'P' button.


### ALT-3 : Set Range BP

This button will ask you the address range in which the break-points will be set.
By using this button, you can set break-points against instructions in the range of 0x8048100 ~ 0x8048200 per se.



### ALT-4 : Create/Setup Module BP

This button helps you to setup breakpoints against starting point of entire functions inside a module(.dll, or .so).
There are two steps in order to do this.

First, you need to open up the module(dll or so) file with IDA.  
After IDA finishes the static analysis of module, press this button to 'Create break-point information and save it into a file'.  
Codemap will ask you the file name of this information.

Second, while you are debugging an application which uses the module(dll or so),
put your cursor inside the memory area of the loaded module and press this button again. 
then Codemap will ask you the name of the file that you stored the break-point information for this module.


### ALT-5 : Connect Codemap Browser Screen to IDA View

This button allows you to connect the IDA with Codemap graph browser.
if you press this button and refresh the Codemap graph browser, the browser and IDA will be connected.
after the connection, the IDA screen will follow your cursor from the graph browser.

If you used 'module breakpoint' feature, Codemap will use the base address of the module as the
base address of EIP, so in such case, you need to specify the 'static module base' address.
(see video explanation in codemap.kr)


### Limitation

Codemap supports all binaries that can be debugged with IDA Pro.
However, ARM binary is not supported yet. (will be supported in future)


### Example Usage

1. Attach/Run binary with IDA Pro.
2. Setup breakpoints where you want to trace with Codemap while program is paused
3. Press alt-1 (Browser will popup and codemap will continue the program)
4. Let program run and generate trace results
5. Press alt-1 again (codemap will pause the program)
6. Execute your SQL statement to visualize the trace.

You can use following SQL statements for example.
- select eip from trace
- select eax,ebx,ecx from trace where eax > ebx - ecx
- select eax from trace where ebx*3 = edx
- select eip from trace limit 100
- select eax from trace order by eax
- select eip from trace where m_edi like 'bla'   (m_ prefix means the memory dump pointed by register)
- select eip from trace where m_arg1 like 'bla'   (in x86, arg1~arg4 is equivalent to *(esp+4) ~ *(esp+16))
- select ecx from trace where m_ecx like 'bla' order by edx limit 10
- select edx+1000 from trace where esi < edi and eax > 100


### Contact for developers

- daehee87@kaist.ac.kr
- zzoru@kaist.ac.kr
- dinggul@kaist.ac.kr


### Academic Reference

KAIST CysecLab (Graduate School of Information Security, School of Computing)
Advisor (Prof. B. Kang)


### Visit http://codemap.kr for more details.
