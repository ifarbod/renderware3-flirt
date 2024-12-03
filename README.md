# Renderware 3.x FLIRT signatures

Tested in various versions of GTA San Andreas (RGL, Steam, 1.01, ...) - it can detect and rename up to ~2,500 functions.

Use this script to apply all *.sig files. You can also put them in the `sig` folder in IDA's installation folder, this way, IDA will pick them up for new executables you open. (Though I don't recommend this method)

```py
import sys
import ida_auto
import ida_funcs
import ida_kernwin
import idautils
from PyQt5 import QtWidgets
from pathlib import Path



# Function to take a snapshot of function addresses and their names
def take_snapshot():
    snapshot = {}
    for func in idautils.Functions():
        func_name = ida_funcs.get_func_name(func)
        snapshot[func] = func_name
    return snapshot

# Function to compare two snapshots and find changes
def compare_snapshots(old_snapshot, new_snapshot):
    changes = {}
    for addr, old_name in old_snapshot.items():
        new_name = new_snapshot.get(addr)
        if new_name is not None and new_name != old_name:
            changes[addr] = (old_name, new_name)
    return changes

def main():
    # Take the initial snapshot
    old_snapshot = take_snapshot()

    apply_sig_dir()

    # Take the new snapshot
    new_snapshot = take_snapshot()

    # Compare the snapshots to find changes
    changes = compare_snapshots(old_snapshot, new_snapshot)

    # Print the changes
    if changes:
        for addr, (old_name, new_name) in changes.items():
            print(f"- {hex(addr)}, {old_name} -> {new_name}")
        print(f"{len(changes)} function(s) had their names changed")
    else:
        print("No functions had their names changed.")


def apply_sig_file():
    file = ida_kernwin.ask_file(0, "*.sig", "Select sig file to apply")
    if not file:
        print("apply_sig_file: user canceled")
        return

    print(f"Apply sig file {file}")
    ida_funcs.plan_to_apply_idasgn(file)
    ida_auto.auto_wait()

def apply_sig_dir():
    sig_dir = Path(sys.executable).parent / 'sig'
    sig_dir = QtWidgets.QFileDialog.getExistingDirectory(None, "Select Your Signatures Directory", str(sig_dir))
    if not sig_dir:
        print("apply_sig_dir: user canceled")
        return

    sig_dir = Path(sig_dir)
    for sig_path in sig_dir.rglob('*.sig'):
        print(f"Apply sig file {sig_path}")
        ida_funcs.plan_to_apply_idasgn(str(sig_path))
        ida_auto.auto_wait()

if __name__ == "__main__":
    main()

```
