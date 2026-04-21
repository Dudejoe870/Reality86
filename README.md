# Reality86
## A **(VERY EXPERIMENTAL WIP NOT WORKING)** fast Cycle-Accurate Nintendo64 Emulator

This emulator does not work yet and has barely anything going for it so don't pay attention to it... for now.

### Goal

The goal is to explore the problem space of JITting a cycle-accurate emulator for a system as complex as the Nintendo64 as see if that's even possible (spoiler alert: I think it is... but definitely not easy to do)

### The Idea

The idea is; basically, to keep track of cycles, and generate a graph of clock cycle dependencies across all of the coprocessors of the N64 at JIT time, so that you can order blocks of JITted instructions correctly to make sure that any visible state to the program at any given clock cycle should (hopefully) match the state read on real hardware on that particular clock cycle.

Also potential for going even further and multithreading this process, so each co-processor can have its own thread and insert memory barriers instead at all the dependency points.

Basically the main thing both of those methods do (the single-threaded and multi-threaded variation) is run X processor until it depends on the behavior from another processor, then runs that processor up to that point, then continues running the other processor until it depends on something again, etc. Almost like an OS scheduler.

This might be accomplished using a form of Sea of Nodes, as really all that is is a graph representation of logic and dependencies of that logic. Put another way, basically a graph of the SSA form of the translated code.

Most of this is not really implemented yet, but the goal is to explore this idea with this emulator.
