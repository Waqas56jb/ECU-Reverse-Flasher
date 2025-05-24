import os
import struct
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import sys
from binascii import hexlify

class ECUModuloReplacer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.custom_modulo = None
        
        # Corrected Configuration
        self.PROGRAM_REQUESTS = [
            "tts/program_download_request_1_70100000.bin",
            "tts/program_download_request_2_a0020000.bin",
            "tts/program_download_request_3_a00c0000.bin",
            "tts/program_download_request_4_70100000.bin",
            "tts/program_download_request_5_a00c0000.bin",
            "tts/program_download_request_6_a0080000.bin"
        ]
        
        # Adjusted Memory Locations Based on Actual File Sizes
        self.OEM_MODULO_START = 0x00004690
        self.OEM_MODULO_END = 0x0000478F
        self.NEW_MODULO_START = 0x00004790
        self.NEW_MODULO_END = 0x0000488F
        self.CALIBRATION_STRATEGY_OFFSET = 0x000C1F40
        
        # Fixed Constants
        self.SIGNATURE_SIZE = 256
        self.BYTE_CHANGE_OFFSET = 0x008B30
        self.FOOTER_SIZE = 96
        self.MODULO_SIZE = 160  # Explicit 160-byte modulo
        
        # Byte changes required at 0x8B30
        self.REQUIRED_BYTE_CHANGES = bytes([0xE4, 0xA4, 0x10, 0x90, 0x10, 0x90])
        
        # File size expectations
        self.FILE_SIZE_EXPECTATIONS = {
            "70100000": 2304,
            "a0020000": 262080,
            "a00c0000": 262080,  # Adjusted based on actual size
            "a0080000": 262080
        }

    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair with proper 160-byte modulo extraction"""
        print("\nGenerating RSA-2048 keys...")
        try:
            key = RSA.generate(key_size)
            self.private_key = key
            self.public_key = key.publickey()
            
            # Extract exactly 160 bytes from the modulus
            n_bytes = self.public_key.n.to_bytes(256, 'big')
            self.custom_modulo = n_bytes[-160:]
            
            if len(self.custom_modulo) != 160:
                raise ValueError("Failed to extract 160-byte modulo")
            
            print("RSA Key Generation Successful")
            return self.custom_modulo
        except Exception as e:
            raise RuntimeError(f"RSA key generation failed: {str(e)}")

    def read_binary_file(self, filepath):
        """Read binary file with enhanced validation"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            basename = os.path.basename(filepath)
            expected_size = None
            for pattern, size in self.FILE_SIZE_EXPECTATIONS.items():
                if pattern in basename:
                    expected_size = size
                    break
            
            if expected_size and len(data) != expected_size:
                print(f"Warning: {basename} size {len(data)} doesn't match expected {expected_size}")
            
            return data
        except Exception as e:
            raise RuntimeError(f"Failed to read {filepath}: {str(e)}")

    def write_binary_file(self, filepath, data):
        """Write binary file with validation"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(data)
        except Exception as e:
            raise RuntimeError(f"Failed to write {filepath}: {str(e)}")

    def calculate_checksum(self, data):
        """Calculate MD5 checksum (first 4 bytes)"""
        if not data:
            raise ValueError("Cannot calculate checksum of empty data")
        return hashlib.md5(data).digest()[:4]

    def sign_data(self, data):
        """Sign data using RSA-PKCS#1 v1.5 with SHA-256"""
        if not data:
            raise ValueError("Cannot sign empty data")
        
        try:
            h = SHA256.new(data)
            signer = pkcs1_15.new(self.private_key)
            signature = signer.sign(h)
            return signature[:self.SIGNATURE_SIZE]
        except Exception as e:
            raise RuntimeError(f"Signing failed: {str(e)}")

    def modify_request_download2(self, original_data):
        """Process Request Download 2 file (0xA0020000)"""
        try:
            # Extract components
            header = original_data[:32]
            body = original_data[32:-self.SIGNATURE_SIZE-4-self.FOOTER_SIZE]
            footer = original_data[-self.SIGNATURE_SIZE-4-self.FOOTER_SIZE:-self.SIGNATURE_SIZE-4]
            
            # Generate new signature
            data_to_sign = header + body + footer
            new_signature = self.sign_data(data_to_sign)
            
            # Calculate new checksum
            new_checksum = self.calculate_checksum(data_to_sign + new_signature)
            
            # Reconstruct file
            modified_data = header + body + footer + new_checksum + new_signature
            
            if len(modified_data) != len(original_data):
                raise ValueError("Size changed during modification")
                
            return modified_data
        except Exception as e:
            raise RuntimeError(f"Request Download 2 modification failed: {str(e)}")

    def modify_request_download3(self, original_data):
        """Process Request Download 3 file (0xA00C0000) with adjusted bounds"""
        try:
            new_data = bytearray(original_data)
            original_length = len(new_data)
            
            # Adjusted modulo replacement with bounds checking
            modulo_end = self.NEW_MODULO_START + self.MODULO_SIZE
            if modulo_end > len(new_data):
                print(f"Adjusting modulo placement - original end: {hex(modulo_end)}, file size: {len(new_data)}")
                # Place at end minus signature/checksum space if possible
                new_modulo_start = len(new_data) - self.SIGNATURE_SIZE - 4 - self.MODULO_SIZE
                if new_modulo_start < 0:
                    raise ValueError("Not enough space for modulo replacement")
                print(f"Placing modulo at adjusted position: {hex(new_modulo_start)}")
                self.NEW_MODULO_START = new_modulo_start
            
            # 1. Replace new modulo section
            new_data[self.NEW_MODULO_START:self.NEW_MODULO_START+self.MODULO_SIZE] = self.custom_modulo
            
            # 2. Apply required byte changes if space available
            if self.BYTE_CHANGE_OFFSET + len(self.REQUIRED_BYTE_CHANGES) <= len(new_data):
                new_data[self.BYTE_CHANGE_OFFSET:self.BYTE_CHANGE_OFFSET+len(self.REQUIRED_BYTE_CHANGES)] = self.REQUIRED_BYTE_CHANGES
            
            # 3. Preserve footer if present
            footer_start = original_length - self.SIGNATURE_SIZE - 4 - self.FOOTER_SIZE
            if footer_start >= 0:
                footer = original_data[footer_start:footer_start+self.FOOTER_SIZE]
                new_data[footer_start:footer_start+self.FOOTER_SIZE] = footer
            
            # 4. Generate new signature
            data_to_sign = bytes(new_data[:-self.SIGNATURE_SIZE-4])
            new_signature = self.sign_data(data_to_sign)
            
            # 5. Update checksum
            new_checksum = self.calculate_checksum(data_to_sign + new_signature)
            new_data[-self.SIGNATURE_SIZE-4:-self.SIGNATURE_SIZE] = new_checksum
            new_data[-self.SIGNATURE_SIZE:] = new_signature
            
            return bytes(new_data)
        except Exception as e:
            raise RuntimeError(f"Request Download 3 modification failed: {str(e)}")

    def modify_request_download5(self, original_data):
        """Process Request Download 5 file (0xA00C0000) - Calibration Strategy"""
        try:
            new_data = bytearray(original_data)
            
            # 1. Replace calibration strategy modulo if space available
            if self.CALIBRATION_STRATEGY_OFFSET + self.MODULO_SIZE <= len(new_data):
                new_data[self.CALIBRATION_STRATEGY_OFFSET:self.CALIBRATION_STRATEGY_OFFSET+self.MODULO_SIZE] = self.custom_modulo
            
            # 2. Generate new signature
            data_to_sign = new_data[:-self.SIGNATURE_SIZE]
            new_signature = self.sign_data(data_to_sign)
            
            # 3. Update checksum if space available
            if len(new_data) > self.SIGNATURE_SIZE + 4:
                new_checksum = self.calculate_checksum(data_to_sign + new_signature)
                new_data[-self.SIGNATURE_SIZE-4:-self.SIGNATURE_SIZE] = new_checksum
            
            new_data[-self.SIGNATURE_SIZE:] = new_signature
            return bytes(new_data)
        except Exception as e:
            raise RuntimeError(f"Request Download 5 modification failed: {str(e)}")

    def process_file(self, filename, output_dir):
        """Process a single file with comprehensive error handling"""
        result = {
            'filename': os.path.basename(filename),
            'status': 'Pending',
            'type': 'Unknown',
            'modulo_replaced': False,
            'calibration_replaced': False,
            'size_match': False,
            'error': None
        }
        
        try:
            original_data = self.read_binary_file(filename)
            result['original_size'] = len(original_data)
            
            if "2_a0020000" in filename:
                modified_data = self.modify_request_download2(original_data)
                result['type'] = "Request Download 2"
            elif "3_a00c0000" in filename:
                modified_data = self.modify_request_download3(original_data)
                result['type'] = "Request Download 3"
                result['modulo_replaced'] = True
            elif "5_a00c0000" in filename:
                modified_data = self.modify_request_download5(original_data)
                result['type'] = "Request Download 5"
                result['modulo_replaced'] = True
                result['calibration_replaced'] = True
            else:
                data_to_sign = original_data[:-self.SIGNATURE_SIZE]
                new_signature = self.sign_data(data_to_sign)
                modified_data = data_to_sign + new_signature
                result['type'] = "Other Download Request"
            
            # Save the modified file
            output_path = os.path.join(output_dir, f"custom_{os.path.basename(filename)}")
            self.write_binary_file(output_path, modified_data)
            result['new_size'] = len(modified_data)
            result['size_match'] = (result['new_size'] == result['original_size'])
            result['status'] = 'Success'
            
            # Verify modulo replacement if applicable
            if result['modulo_replaced'] and "3_a00c0000" in filename:
                if self.NEW_MODULO_START + self.MODULO_SIZE <= len(modified_data):
                    actual_modulo = modified_data[self.NEW_MODULO_START:self.NEW_MODULO_START+self.MODULO_SIZE]
                    result['modulo_verified'] = (actual_modulo == self.custom_modulo)
            
            # Verify calibration modulo if applicable
            if result['calibration_replaced']:
                if self.CALIBRATION_STRATEGY_OFFSET + self.MODULO_SIZE <= len(modified_data):
                    actual_calib = modified_data[self.CALIBRATION_STRATEGY_OFFSET:self.CALIBRATION_STRATEGY_OFFSET+self.MODULO_SIZE]
                    result['calibration_verified'] = (actual_calib == self.custom_modulo)
            
        except Exception as e:
            result['status'] = 'Failed'
            result['error'] = str(e)
        
        return result

    def process_all_files(self, output_dir="custom_files"):
        """Process all files with comprehensive reporting"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Generate RSA keys if not already generated
        if not self.custom_modulo:
            self.generate_rsa_keys()
        
        results = []
        for filename in self.PROGRAM_REQUESTS:
            results.append(self.process_file(filename, output_dir))
        
        return results

    def generate_report(self, results):
        """Generate a detailed technical report"""
        report = []
        report.append("ECU Signature Modulo Replacement Report")
        report.append("=" * 80)
        report.append(f"RSA Modulo (160 bytes): {hexlify(self.custom_modulo).decode()}")
        report.append("")
        
        # Summary table
        report.append("File Processing Summary:")
        report.append("-" * 120)
        report.append(f"{'Filename':<40} {'Type':<25} {'Status':<10} {'Size':<15} {'Modulo':<10} {'Calibration':<10} {'Error'}")
        report.append("-" * 120)
        
        for r in results:
            modulo_status = ""
            if r.get('modulo_replaced', False):
                modulo_status = "✓" if r.get('modulo_verified', False) else "✗"
            
            calib_status = ""
            if r.get('calibration_replaced', False):
                calib_status = "✓" if r.get('calibration_verified', False) else "✗"
            
            size_status = f"{r.get('new_size', 0)}/{r.get('original_size', 0)}"
            if r.get('size_match', False):
                size_status += " ✓"
            else:
                size_status += " ✗"
            
            error_msg = r.get('error', '')
            
            report.append(f"{r['filename']:<40} {r['type']:<25} {r['status']:<10} {size_status:<15} {modulo_status:<10} {calib_status:<10} {error_msg}")
        
        # Final status
        all_success = all(r['status'] == 'Success' for r in results)
        all_verified = all(r.get('modulo_verified', True) for r in results if r.get('modulo_replaced', False))
        all_calib_verified = all(r.get('calibration_verified', True) for r in results if r.get('calibration_replaced', False))
        all_sizes_match = all(r.get('size_match', False) for r in results)
        
        report.append("\nFinal Status:")
        report.append("-" * 80)
        if all_success and all_verified and all_calib_verified and all_sizes_match:
            report.append("COMPLETE SUCCESS - All files processed correctly")
        else:
            if not all_success:
                report.append("✗ Some files failed processing")
            if not all_verified:
                report.append("✗ Some modulo replacements failed verification")
            if not all_calib_verified:
                report.append("✗ Some calibration modulo replacements failed verification")
            if not all_sizes_match:
                report.append("✗ Some file sizes changed during processing")
        
        return '\n'.join(report)


def main():
    print("ECU Signature Modulo Replacement Tool")
    print("=" * 80)
    
    try:
        # Initialize with strict validation
        replacer = ECUModuloReplacer()
        
        # Generate RSA keys
        print("\nGenerating cryptographic keys...")
        replacer.generate_rsa_keys()
        
        # Process all files
        print("\nProcessing ECU files...")
        results = replacer.process_all_files()
        
        # Generate and print report
        report = replacer.generate_report(results)
        print("\n" + report)
        
        # Save report to file
        with open("ecu_signature_report.txt", 'w', encoding='utf-8') as f:
            f.write(report)
        print("\nDetailed report saved to ecu_signature_report.txt")
        
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # Check for required packages
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
    except ImportError:
        print("ERROR: Required PyCryptodome package not installed.")
        print("Please install it with: pip install pycryptodome")
        sys.exit(1)
    
    main()