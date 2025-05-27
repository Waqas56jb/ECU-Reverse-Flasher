import os
import subprocess
import json
import hashlib
from pathlib import Path

class ECUReverseEngineer:
    def __init__(self):
        # Verified paths from your system
        self.ghidra_path = r"C:\Users\S\Downloads\ghidra_v10.0.1\ghidra_10.0.1_PUBLIC\support\analyzeHeadless.bat"
        self.java_home = r"C:\Eclipse Adoptium\jdk-11.0.27+6"
        self.project_root = r"D:\Shehrayar Romi\ECU-Reverse-Flasher"
        
        # Configuration
        self.project_dir = os.path.join(self.project_root, "ECU_Analysis")
        self.binaries = {
            "Request2": os.path.join(self.project_root, "tts", "program_download_request_2_a0020000.bin"),
            "Request3": os.path.join(self.project_root, "tts", "program_download_request_3_a00c0000.bin"),
            "Request5": os.path.join(self.project_root, "tts", "program_download_request_5_a00c0000.bin")
        }
        
        # Environment setup
        self.env = os.environ.copy()
        self.env["JAVA_HOME"] = self.java_home
        self.env["PATH"] = f"{self.java_home}\\bin;{self.env['PATH']}"
        
        # Verify installations
        self.verify_installation()

    def verify_installation(self):
        """Validate critical paths and installations"""
        missing = []
        if not os.path.exists(self.ghidra_path):
            missing.append(f"Ghidra (path: {self.ghidra_path})")
        if not os.path.exists(self.java_home):
            missing.append(f"Java 11 (path: {self.java_home})")
        
        for name, path in self.binaries.items():
            if not os.path.exists(path):
                missing.append(f"Binary {name} (path: {path})")
        
        if missing:
            raise FileNotFoundError(
                "Missing critical components:\n- " + "\n- ".join(missing)
            )

    def run_ghidra_analysis(self, name, binary_path):
        """Execute Ghidra analysis with proper path handling"""
        print(f"Analyzing {name}...")
        
        # Generate unique project name
        file_hash = hashlib.sha256(open(binary_path, 'rb').read()).hexdigest()[:8]
        project_name = f"ECU_{name}_{file_hash}"
        script_path = os.path.join(self.project_dir, f"analyze_{name}.py")
        
        # Create Ghidra script
        self.create_analysis_script(script_path)
        
        # Build command with proper quoting
        cmd = [
            f'"{self.ghidra_path}"',
            f'"{self.project_dir}"',
            project_name,
            "-import", f'"{binary_path}"',
            "-postScript", f'"{script_path}"',
            "-deleteProject",
            "-noanalysis"
        ]
        
        try:
            result = subprocess.run(
                " ".join(cmd),
                shell=True,
                env=self.env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output_file = os.path.join(self.project_dir, f"{name}_analysis.json")
            if os.path.exists(output_file):
                print(f"✅ Success - {name} analysis complete")
            else:
                print(f"⚠️ Warning - No output for {name}")
                print(f"Ghidra output:\n{result.stdout}\n{result.stderr}")
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to analyze {name}")
            print(f"Error:\n{e.stderr}")
            print(f"Command:\n{' '.join(cmd)}")

    def create_analysis_script(self, script_path):
        """Generate Ghidra analysis script"""
        script = """
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
        with open('%s', 'w') as f:
            json.dump(results, f)
    except Exception as e:
        with open('ghidra_errors.log', 'a') as f:
            f.write(f"Error: {str(e)}\\n")

analyze()
""" % script_path.replace("\\", "\\\\")
        
        with open(script_path, 'w') as f:
            f.write(script)

    def generate_report(self):
        """Generate final analysis report"""
        report = [
            "ECU Reverse Engineering Report",
            "="*80,
            f"Ghidra Path: {self.ghidra_path}",
            f"Java Home: {self.java_home}",
            f"Project Directory: {self.project_dir}",
            "\nAnalyzed Files:",
            "-"*80
        ]
        
        for name in self.binaries:
            result_file = os.path.join(self.project_dir, f"{name}_analysis.json")
            if os.path.exists(result_file):
                with open(result_file) as f:
                    data = json.load(f)
                report.append(f"\n{name}:")
                report.append(f"  - Name: {data['info']['name']}")
                report.append(f"  - Language: {data['info']['language']}")
                report.append(f"  - Entry Point: {data['info']['entry_point']}")
            else:
                report.append(f"\n{name}: ❌ Analysis failed")
        
        report_path = os.path.join(self.project_dir, "ecu_analysis_report.txt")
        with open(report_path, 'w') as f:
            f.write("\n".join(report))
        print(f"\n📄 Final report: {report_path}")

if __name__ == "__main__":
    print("ECU Reverse Engineering Analysis")
    print("="*80)
    
    try:
        analyzer = ECUReverseEngineer()
        Path(analyzer.project_dir).mkdir(exist_ok=True)
        
        print("\nVerified Components:")
        print(f"- Ghidra: {analyzer.ghidra_path}")
        print(f"- Java 11: {analyzer.java_home}")
        print("- Binaries:")
        for name, path in analyzer.binaries.items():
            print(f"  - {name}: {path}")
        
        print("\nStarting analysis...")
        for name, path in analyzer.binaries.items():
            analyzer.run_ghidra_analysis(name, path)
        
        analyzer.generate_report()
        
    except Exception as e:
        print(f"\n❌ Critical error: {str(e)}")
        print("Please verify:")
        print("1. All paths exist")
        print("2. Java 11 is installed")
        print("3. Binaries are in tts/ directory")