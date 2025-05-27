
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def analyze():
    results = {}
    try:
        program = currentProgram
        results['info'] = {
            'name': program.getName(),
            'language': program.getLanguage().toString(),
            'entry_point': hex(program.getMinAddress().getOffset())
        }
        with open('D:\\Shehrayar Romi\\ECU-Reverse-Flasher\\ECU_Analysis\\analyze_Request2.py', 'w') as f:
            json.dump(results, f)
    except Exception as e:
        with open('ghidra_errors.log', 'a') as f:
            f.write(f"Error: {str(e)}\n")

analyze()
