#!/usr/bin/env python3
"""
AI-Powered PCAP Analyzer for SOC Operations
Universal version - Works with ANY Ollama model
Converts PCAP to structured JSON for better AI analysis
"""

import argparse
import json
import logging
import requests
import os
import sys
from scapy.all import PcapReader, IP, TCP, UDP, DNS, ICMP, ARP, Raw, Ether
from collections import Counter
from datetime import datetime


class PCAPAnalyzer:
    def __init__(self, pcap_file, ollama_model="llama3.2"):
        """
        Initialize the PCAP analyzer
        
        Args:
            pcap_file: Path to PCAP file
            ollama_model: Name of Ollama model to use (default: llama3.2)
                         Examples: llama3.2, mistral, qwen2.5:0.5b, etc.
        """
        self.pcap_file = pcap_file
        self.ollama_model = ollama_model
        self.packet_count = 0
        self.logger = self.setup_logging()
        
    def setup_logging(self):
        """Setup logging system"""
        logger = logging.getLogger('PCAPAnalyzer')
        logger.setLevel(logging.INFO)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(ch)
        
        return logger
    
    def check_ollama(self):
        """Check if Ollama is running and model is available"""
        self.logger.info("Checking Ollama connection...")
        
        try:
            # Check if Ollama is running
            response = requests.get("http://localhost:11434/api/tags", timeout=10)
            
            if response.status_code == 200:
                available_models = [model['name'] for model in response.json().get('models', [])]
                
                if not available_models:
                    self.logger.error("No models found in Ollama. Please pull a model first.")
                    self.logger.info("Example: ollama pull llama3.2")
                    return False, []
                
                self.logger.info(f"Found {len(available_models)} model(s) in Ollama")
                
                # Check if requested model exists
                model_exists = any(self.ollama_model in model_name for model_name in available_models)
                
                if model_exists:
                    self.logger.info(f"✅ Model '{self.ollama_model}' is available")
                    return True, available_models
                else:
                    self.logger.warning(f"Model '{self.ollama_model}' not found in Ollama")
                    self.logger.info(f"Available models: {', '.join(available_models)}")
                    # Auto-select first available model
                    self.ollama_model = available_models[0]
                    self.logger.info(f"Auto-selected model: {self.ollama_model}")
                    return True, available_models
            
            else:
                self.logger.error(f"Ollama API returned status: {response.status_code}")
                return False, []
                
        except requests.exceptions.ConnectionError:
            self.logger.error("❌ Cannot connect to Ollama. Is it running?")
            self.logger.info("Start Ollama with: ollama serve")
            return False, []
        except Exception as e:
            self.logger.error(f"Error checking Ollama: {e}")
            return False, []
    
    def load_pcap(self):
        """Load PCAP file and count packets using streaming"""
        self.logger.info(f"Loading PCAP file: {self.pcap_file}")
        
        if not os.path.exists(self.pcap_file):
            self.logger.error(f"PCAP file not found: {self.pcap_file}")
            return False
        
        try:
            # Count packets first
            self.packet_count = 0
            with PcapReader(self.pcap_file) as pcap_reader:
                for _ in pcap_reader:
                    self.packet_count += 1
            
            self.logger.info(f"✓ File contains {self.packet_count:,} packets")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error loading PCAP: {str(e)}")
            return False
    
    def packet_to_dict(self, pkt, index):
        """Convert a single packet to dictionary format"""
        packet_dict = {
            "packet_number": index + 1,
            "timestamp": float(pkt.time) if hasattr(pkt, 'time') else None,
            "length": len(pkt),
            "protocols": []
        }
        
        try:
            # Ethernet layer
            if Ether in pkt:
                packet_dict["ethernet"] = {
                    "src_mac": pkt[Ether].src,
                    "dst_mac": pkt[Ether].dst,
                    "type": pkt[Ether].type
                }
                packet_dict["protocols"].append("Ethernet")
            
            # IP layer
            if IP in pkt:
                packet_dict["ip"] = {
                    "version": pkt[IP].version,
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "ttl": pkt[IP].ttl,
                    "protocol": pkt[IP].proto,
                    "flags": str(pkt[IP].flags),
                    "length": pkt[IP].len
                }
                packet_dict["protocols"].append("IP")
                
                # TCP layer
                if TCP in pkt:
                    packet_dict["tcp"] = {
                        "src_port": pkt[TCP].sport,
                        "dst_port": pkt[TCP].dport,
                        "seq": pkt[TCP].seq,
                        "ack": pkt[TCP].ack,
                        "flags": str(pkt[TCP].flags),
                        "window": pkt[TCP].window
                    }
                    packet_dict["protocols"].append("TCP")
                    
                    # Extract payload if exists
                    if Raw in pkt:
                        try:
                            payload = bytes(pkt[Raw].load)
                            packet_dict["tcp"]["payload_hex"] = payload[:100].hex()
                            packet_dict["tcp"]["payload_length"] = len(payload)
                            packet_dict["tcp"]["payload_ascii"] = payload[:100].decode('ascii', errors='ignore')
                        except Exception as e:
                            self.logger.debug(f"Payload parsing error: {e}")
                
                # UDP layer
                elif UDP in pkt:
                    packet_dict["udp"] = {
                        "src_port": pkt[UDP].sport,
                        "dst_port": pkt[UDP].dport,
                        "length": pkt[UDP].len
                    }
                    packet_dict["protocols"].append("UDP")
                    
                    if Raw in pkt:
                        try:
                            payload = bytes(pkt[Raw].load)
                            packet_dict["udp"]["payload_hex"] = payload[:100].hex()
                            packet_dict["udp"]["payload_length"] = len(payload)
                        except Exception as e:
                            self.logger.debug(f"UDP payload parsing error: {e}")
                
                # ICMP layer
                elif ICMP in pkt:
                    packet_dict["icmp"] = {
                        "type": pkt[ICMP].type,
                        "code": pkt[ICMP].code
                    }
                    packet_dict["protocols"].append("ICMP")
            
            # DNS layer
            if DNS in pkt:
                try:
                    packet_dict["dns"] = {
                        "query_response": "response" if pkt[DNS].qr == 1 else "query",
                        "questions": [],
                        "answers": []
                    }
                    
                    if pkt[DNS].qd:
                        try:
                            qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore') if pkt[DNS].qd.qname else ""
                            packet_dict["dns"]["questions"].append({
                                "name": qname,
                                "type": pkt[DNS].qd.qtype,
                                "class": pkt[DNS].qd.qclass
                            })
                        except Exception as e:
                            self.logger.debug(f"DNS question parsing error: {e}")
                    
                    if pkt[DNS].an:
                        try:
                            for i in range(min(pkt[DNS].ancount, 10)):
                                answer = pkt[DNS].an[i] if hasattr(pkt[DNS].an, '__getitem__') else pkt[DNS].an
                                packet_dict["dns"]["answers"].append({
                                    "name": answer.rrname.decode('utf-8', errors='ignore') if hasattr(answer, 'rrname') else "",
                                    "type": answer.type if hasattr(answer, 'type') else None,
                                    "data": str(answer.rdata) if hasattr(answer, 'rdata') else ""
                                })
                        except Exception as e:
                            self.logger.debug(f"DNS answer parsing error: {e}")
                    
                    packet_dict["protocols"].append("DNS")
                except Exception as e:
                    self.logger.warning(f"DNS parsing error: {e}")
            
            # ARP layer
            if ARP in pkt:
                packet_dict["arp"] = {
                    "operation": "request" if pkt[ARP].op == 1 else "reply",
                    "src_mac": pkt[ARP].hwsrc,
                    "src_ip": pkt[ARP].psrc,
                    "dst_mac": pkt[ARP].hwdst,
                    "dst_ip": pkt[ARP].pdst
                }
                packet_dict["protocols"].append("ARP")
                
        except Exception as e:
            self.logger.error(f"Error processing packet {index + 1}: {e}")
            packet_dict["parse_error"] = str(e)
        
        return packet_dict
    
    def generate_statistics(self):
        """Generate statistics from PCAP using streaming"""
        self.logger.info("Generating statistics...")
        
        stats = {
            "protocols": {},
            "top_talkers": {
                "source_ips": [],
                "destination_ips": [],
                "source_ports": [],
                "destination_ports": []
            },
            "dns": {
                "total_queries": 0,
                "unique_domains": [],
                "top_queried_domains": []
            },
            "traffic_patterns": {
                "total_bytes": 0,
                "average_packet_size": 0
            }
        }
        
        try:
            protocol_counter = Counter()
            src_ips = Counter()
            dst_ips = Counter()
            src_ports = Counter()
            dst_ports = Counter()
            dns_queries = []
            total_bytes = 0
            
            # Process packets with streaming
            with PcapReader(self.pcap_file) as pcap_reader:
                packet_idx = 0
                for pkt in pcap_reader:
                    try:
                        total_bytes += len(pkt)
                        
                        if IP in pkt:
                            src_ips[pkt[IP].src] += 1
                            dst_ips[pkt[IP].dst] += 1
                            
                            if TCP in pkt:
                                protocol_counter['TCP'] += 1
                                src_ports[pkt[TCP].sport] += 1
                                dst_ports[pkt[TCP].dport] += 1
                            elif UDP in pkt:
                                protocol_counter['UDP'] += 1
                                src_ports[pkt[UDP].sport] += 1
                                dst_ports[pkt[UDP].dport] += 1
                            elif ICMP in pkt:
                                protocol_counter['ICMP'] += 1
                        
                        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                            try:
                                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                                dns_queries.append(qname)
                            except:
                                pass
                        
                        if ARP in pkt:
                            protocol_counter['ARP'] += 1
                        
                        packet_idx += 1
                        if packet_idx % 10000 == 0:
                            self.logger.info(f"Statistics: processed {packet_idx:,} packets")
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing packet {packet_idx}: {e}")
            
            # Fill statistics
            stats["protocols"] = dict(protocol_counter)
            stats["top_talkers"]["source_ips"] = [{"ip": ip, "count": count} for ip, count in src_ips.most_common(10)]
            stats["top_talkers"]["destination_ips"] = [{"ip": ip, "count": count} for ip, count in dst_ips.most_common(10)]
            stats["top_talkers"]["source_ports"] = [{"port": port, "count": count} for port, count in src_ports.most_common(10)]
            stats["top_talkers"]["destination_ports"] = [{"port": port, "count": count} for port, count in dst_ports.most_common(10)]
            
            stats["dns"]["total_queries"] = len(dns_queries)
            stats["dns"]["unique_domains"] = list(set(dns_queries))[:50]
            dns_counter = Counter(dns_queries)
            stats["dns"]["top_queried_domains"] = [{"domain": domain, "count": count} for domain, count in dns_counter.most_common(20)]
            
            stats["traffic_patterns"]["total_bytes"] = total_bytes
            if self.packet_count > 0:
                stats["traffic_patterns"]["average_packet_size"] = total_bytes / self.packet_count
            
            self.logger.info("✓ Statistics generated")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {"error": str(e)}
    
    def generate_security_analysis(self):
        """Generate security-focused analysis"""
        self.logger.info("Generating security analysis...")
        
        security = {
            "threat_indicators": [],
            "suspicious_ports": [],
            "potential_attacks": [],
            "risk_score": 0
        }
        
        try:
            suspicious_ports = [4444, 5555, 6666, 31337, 1337, 8888, 9999, 6667, 6697]
            exploit_ports = [445, 139, 3389, 135, 1433, 3306]
            
            src_ips = Counter()
            dst_ips = Counter()
            
            # Process packets with streaming
            with PcapReader(self.pcap_file) as pcap_reader:
                packet_idx = 0
                for pkt in pcap_reader:
                    try:
                        if IP in pkt:
                            src_ips[pkt[IP].src] += 1
                            dst_ips[pkt[IP].dst] += 1
                            
                            if TCP in pkt:
                                # Suspicious ports
                                if pkt[TCP].dport in suspicious_ports:
                                    security["suspicious_ports"].append({
                                        "port": pkt[TCP].dport,
                                        "src_ip": pkt[IP].src,
                                        "dst_ip": pkt[IP].dst,
                                        "description": "Known malicious/backdoor port"
                                    })
                                
                                # Exploit ports
                                if pkt[TCP].dport in exploit_ports:
                                    security["threat_indicators"].append({
                                        "type": "Exploit Port Access",
                                        "port": pkt[TCP].dport,
                                        "src_ip": pkt[IP].src,
                                        "severity": "high"
                                    })
                        
                        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
                            try:
                                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                                
                                # Check for suspicious domains
                                suspicious_keywords = ['malware', 'botnet', 'c2', 'ransomware', 'phish', 'hack']
                                if any(kw in qname.lower() for kw in suspicious_keywords):
                                    security["threat_indicators"].append({
                                        "type": "Suspicious DNS Query",
                                        "domain": qname,
                                        "severity": "critical"
                                    })
                            except:
                                pass
                        
                        packet_idx += 1
                        if packet_idx % 10000 == 0:
                            self.logger.info(f"Security analysis: processed {packet_idx:,} packets")
                            
                    except Exception as e:
                        self.logger.debug(f"Error processing packet {packet_idx}: {e}")
            
            # Port scan detection
            for ip, count in src_ips.items():
                if count > 50:  # Threshold
                    unique_dst_ports = set()
                    with PcapReader(self.pcap_file) as pcap_reader:
                        for pkt in pcap_reader:
                            if IP in pkt and pkt[IP].src == ip and TCP in pkt:
                                unique_dst_ports.add(pkt[TCP].dport)
                    
                    if len(unique_dst_ports) > 20:
                        security["potential_attacks"].append({
                            "type": "Port Scan",
                            "src_ip": ip,
                            "packets": count,
                            "unique_ports": len(unique_dst_ports),
                            "severity": "high"
                        })
            
            # DDoS detection
            top_dst = dst_ips.most_common(1)
            if top_dst and self.packet_count > 0:
                if top_dst[0][1] > self.packet_count * 0.5:  # 50% threshold
                    security["potential_attacks"].append({
                        "type": "Potential DDoS",
                        "target_ip": top_dst[0][0],
                        "packets": top_dst[0][1],
                        "percentage": (top_dst[0][1] / self.packet_count) * 100,
                        "severity": "critical"
                    })
            
            # Calculate risk score
            risk_score = 0
            risk_score += len(security["threat_indicators"]) * 20
            risk_score += len(security["potential_attacks"]) * 25
            risk_score += len(security["suspicious_ports"]) * 10
            security["risk_score"] = min(risk_score, 100)
            
            self.logger.info("✓ Security analysis generated")
            return security
            
        except Exception as e:
            self.logger.error(f"Error generating security analysis: {e}")
            return {"error": str(e)}
    
    def convert_to_json(self, max_packets=None):
        """Convert PCAP to JSON format with optional packet limit"""
        if max_packets:
            self.logger.info(f"Converting up to {max_packets:,} packets to JSON...")
        else:
            self.logger.info("Converting packets to JSON...")
        
        json_data = {
            "metadata": {
                "filename": self.pcap_file,
                "total_packets": self.packet_count,
                "analysis_timestamp": datetime.now().isoformat()
            },
            "statistics": {},
            "security_analysis": {}
        }
        
        try:
            # Generate statistics and security analysis
            json_data["statistics"] = self.generate_statistics()
            json_data["security_analysis"] = self.generate_security_analysis()
            
            # Convert some packets to JSON for AI analysis
            packets_for_ai = []
            with PcapReader(self.pcap_file) as pcap_reader:
                for idx, pkt in enumerate(pcap_reader):
                    if max_packets and idx >= max_packets:
                        break
                    
                    try:
                        packet_dict = self.packet_to_dict(pkt, idx)
                        packets_for_ai.append(packet_dict)
                    except Exception as e:
                        self.logger.warning(f"Could not parse packet {idx + 1}: {e}")
                    
                    if (idx + 1) % 1000 == 0:
                        self.logger.info(f"Converted {idx + 1:,} packets...")
            
            # Add sample packets to JSON (limited to save space)
            sample_size = min(len(packets_for_ai), 100)  # Send max 100 packets to AI
            json_data["sample_packets"] = packets_for_ai[:sample_size]
            
            self.logger.info(f"✓ JSON conversion complete")
            return json_data
            
        except Exception as e:
            self.logger.error(f"Error converting to JSON: {e}")
            return json_data
    
    def analyze_with_ai(self, json_data):
        """Analyze JSON data with Ollama model"""
        self.logger.info(f"Starting AI analysis with model: {self.ollama_model}")
        
        try:
            url = "http://localhost:11434/api/generate"
            
            # Create prompt for AI
            prompt = self.create_ai_prompt(json_data)
            
            # Send to Ollama
            response = requests.post(
                url,
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2000
                    }
                },
                timeout=180  # 3 minutes timeout
            )
            
            if response.status_code == 200:
                ai_response = response.json().get('response', 'No response')
                self.logger.info("✓ AI analysis complete")
                return self.clean_ai_response(ai_response)
            else:
                error_msg = f"AI request failed: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return f"❌ {error_msg}"
                
        except requests.exceptions.ConnectionError:
            error_msg = "❌ Cannot connect to Ollama. Make sure 'ollama serve' is running."
            self.logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"❌ AI analysis error: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
    
    def create_ai_prompt(self, json_data):
        """Create optimized prompt for AI analysis"""
        # Extract key information
        metadata = json_data["metadata"]
        stats = json_data["statistics"]
        security = json_data["security_analysis"]
        
        summary = {
            "total_packets": metadata["total_packets"],
            "protocol_distribution": stats.get("protocols", {}),
            "top_source_ips": stats.get("top_talkers", {}).get("source_ips", [])[:5],
            "top_destination_ips": stats.get("top_talkers", {}).get("destination_ips", [])[:5],
            "risk_score": security.get("risk_score", 0),
            "threat_indicators": len(security.get("threat_indicators", [])),
            "potential_attacks": len(security.get("potential_attacks", [])),
            "sample_packet_count": len(json_data.get("sample_packets", []))
        }
        
        prompt = f"""You are an expert cybersecurity analyst. Analyze this network traffic data:

SUMMARY:
- Total packets: {summary['total_packets']:,}
- Protocols: {summary['protocol_distribution']}
- Risk Score: {summary['risk_score']}/100
- Threat indicators: {summary['threat_indicators']}
- Potential attacks: {summary['potential_attacks']}

DETAILED FINDINGS:
{json.dumps(security, indent=2)}

SAMPLE TRAFFIC (first {summary['sample_packet_count']} packets):
{json.dumps(json_data.get('sample_packets', []), indent=2)[:4000]}

Please provide a security analysis with:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. CRITICAL FINDINGS (immediate threats)
3. ATTACK INDICATORS (patterns found)
4. RISK LEVEL (Low/Medium/High/Critical)
5. RECOMMENDATIONS (actionable steps)
6. IOCs (IPs, domains, ports to investigate)

Be specific and cite evidence."""
        
        return prompt
    
    def clean_ai_response(self, response):
        """Clean up AI response"""
        # Remove markdown code blocks if present
        if response.startswith('```'):
            lines = response.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].startswith('```'):
                lines = lines[:-1]
            response = '\n'.join(lines)
        
        # Remove extra whitespace
        response = response.strip()
        
        return response
    
    def save_report(self, json_data, ai_analysis, output_file=None):
        """Save complete analysis report"""
        try:
            if not output_file:
                base_name = os.path.splitext(self.pcap_file)[0]
                output_file = f"{base_name}_analysis_report.json"
            
            full_report = {
                "metadata": json_data["metadata"],
                "model_used": self.ollama_model,
                "statistics": json_data["statistics"],
                "security_analysis": json_data["security_analysis"],
                "ai_analysis": ai_analysis,
                "generated_at": datetime.now().isoformat()
            }
            
            with open(output_file, 'w') as f:
                json.dump(full_report, f, indent=2)
            
            self.logger.info(f"💾 Report saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            return None
    
    def run_analysis(self, max_packets=None, output_file=None):
        """Run complete analysis pipeline"""
        self.logger.info("="*60)
        self.logger.info("Starting PCAP Analysis")
        self.logger.info("="*60)
        
        # Check Ollama
        ollama_ok, models = self.check_ollama()
        if not ollama_ok:
            self.logger.error("Ollama check failed. Analysis cannot continue.")
            return False
        
        # Load PCAP
        if not self.load_pcap():
            return False
        
        # Convert to JSON
        json_data = self.convert_to_json(max_packets)
        
        # Display summary
        self.print_summary(json_data)
        
        # AI Analysis
        self.logger.info("-"*60)
        ai_analysis = self.analyze_with_ai(json_data)
        
        if ai_analysis and not ai_analysis.startswith("❌"):
            print("\n" + "="*60)
            print("🤖 AI SECURITY ANALYSIS")
            print("="*60)
            print(ai_analysis)
        
        # Save report
        report_file = self.save_report(json_data, ai_analysis, output_file)
        
        self.logger.info("="*60)
        self.logger.info("✅ Analysis Complete!")
        
        if report_file:
            print(f"\n📁 Report saved: {report_file}")
        
        return True
    
    def print_summary(self, json_data):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("📊 ANALYSIS SUMMARY")
        print("="*60)
        
        stats = json_data["statistics"]
        security = json_data["security_analysis"]
        
        print(f"Total Packets: {json_data['metadata']['total_packets']:,}")
        
        if "protocols" in stats:
            print(f"\n📈 Protocol Distribution:")
            for proto, count in stats["protocols"].items():
                print(f"  {proto}: {count:,}")
        
        print(f"\n🔒 Security Assessment:")
        print(f"  Risk Score: {security.get('risk_score', 0)}/100")
        
        if "threat_indicators" in security:
            print(f"  Threat Indicators: {len(security['threat_indicators'])}")
        
        if "potential_attacks" in security:
            print(f"  Potential Attacks: {len(security['potential_attacks'])}")
        
        if "top_talkers" in stats and "source_ips" in stats["top_talkers"]:
            print(f"\n🌐 Top Source IPs:")
            for ip_info in stats["top_talkers"]["source_ips"][:3]:
                print(f"  {ip_info['ip']}: {ip_info['count']:,} packets")


def main():
    parser = argparse.ArgumentParser(
        description='Universal AI-Powered PCAP Analyzer - Works with ANY Ollama Model',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Universal Model Support:
  ======================
  This tool works with ANY Ollama model. Just specify the model name!
  
  Examples:
    --model llama3.2
    --model mistral
    --model qwen2.5:0.5b
    --model qwen2.5:0.5b-instruct-gguf
    --model codellama
    --model phi3:mini
  
  How to use:
  1. Install Ollama: https://ollama.ai
  2. Pull a model: ollama pull MODEL_NAME
  3. Run analyzer: python pcap_analyzer.py capture.pcap --model MODEL_NAME
  
  Example with Qwen2.5-0.5B-Instruct-GGUF:
    ollama pull qwen2.5:0.5b
    python pcap_analyzer.py capture.pcap --model qwen2.5:0.5b
  
  The tool will automatically:
  - Check if Ollama is running
  - Verify the model exists
  - Use the model for analysis
  - Generate a comprehensive security report

Options:
  -m, --model MODEL    Ollama model name (default: llama3.2)
  --max-packets N      Maximum packets to analyze (default: all)
  -o, --output FILE    Output report filename
        """
    )
    
    parser.add_argument('pcap_file', help='Path to PCAP/PCAPNG file')
    parser.add_argument('-m', '--model', default='llama3.2',
                       help='Ollama model name (default: llama3.2)')
    parser.add_argument('--max-packets', type=int, default=None,
                       help='Maximum packets to analyze (default: all)')
    parser.add_argument('-o', '--output', help='Output report filename')
    
    args = parser.parse_args()
    
    # Banner
    print("\n" + "="*60)
    print("🔒 UNIVERSAL AI-POWERED PCAP ANALYZER")
    print("="*60)
    print(f"📁 File: {args.pcap_file}")
    print(f"🤖 Model: {args.model}")
    if args.max_packets:
        print(f"📊 Packets: Up to {args.max_packets:,}")
    else:
        print(f"📊 Packets: ALL")
    print("💾 Memory-optimized streaming enabled")
    print("="*60)
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer(args.pcap_file, args.model)
    
    # Run analysis
    analyzer.run_analysis(
        max_packets=args.max_packets,
        output_file=args.output
    )


if __name__ == "__main__":
    main()