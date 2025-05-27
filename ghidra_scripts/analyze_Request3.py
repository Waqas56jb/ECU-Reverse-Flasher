
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def analyze():
    results = {}
    program = currentProgram
    
    # Basic info
    results['info'] = {
        'name': program.getName(),
        'language': program.getLanguage().toString(),
        'entry_point': hex(program.getMinAddress().getOffset())
    }
    
    # Memory analysis
    results['memory'] = []
    for block in program.getMemory().getBlocks():
        results['memory'].append({
            'name': block.getName(),
            'start': hex(block.getStart().getOffset()),
            'end': hex(block.getEnd().getOffset()),
            'size': block.getSize()
        })
    
    # Save results
    with open(r'Request3_analysis.json', 'w') as f:
        json.dump(results, f, indent=2)

analyze()
