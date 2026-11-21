"""
Crypto Module - Cryptocurrency Intelligence
"""

import argparse
import hashlib
import os
import re
from typing import Dict, Any, List, Optional

from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner
from vortexosint.core.output import (
    flatten_dict as _flatten_dict,
    format_dict as _format_dict,
    format_results_csv as _format_results_csv,
    format_results_txt as _format_results_txt,
    output_results as _output_results,
)

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}
_BECH32_RE = re.compile(r"^(bc1|ltc1|bnb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,87}$")
_ETH_ADDR_RE = re.compile(r"^0[xX][0-9a-fA-F]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEADERS = {"User-Agent": "VortexOSINT/1.0"}


def run(args: argparse.Namespace) -> int:
    """Run the Crypto module."""
    print_module_banner("CRYPTO", "Cryptocurrency Intelligence & Blockchain Analysis")

    targets = []
    if args.address:
        targets.append(('address', args.address))
    if args.tx:
        targets.append(('transaction', args.tx))
    if args.entity:
        targets.append(('entity', args.entity))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --address, --tx, or --entity{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Analyzing {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = analyze_target(target_type, target_value, args)
        results[target_value] = result

    output_results(results, args)
    return 0


def analyze_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    if target_type == 'address':
        result['findings'] = analyze_address(target_value, args)
    elif target_type == 'transaction':
        result['findings'] = analyze_transaction(target_value, args)
    elif target_type == 'entity':
        result['findings'] = analyze_entity(target_value, args)

    return result


def analyze_address(address: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze cryptocurrency address."""
    requested_chain = getattr(args, 'blockchain', 'all')
    blockchain = detect_blockchain(address) if requested_chain == 'all' else requested_chain
    valid = validate_address(address, blockchain)
    balance = get_balance(address, blockchain) if valid else {'error': 'invalid address'}
    txs = get_transactions(address, blockchain, args.depth) if (valid and args.depth > 0) else []
    findings = {
        'address': address,
        'blockchain': blockchain,
        'valid': valid,
        'balance': balance,
        'transactions': txs,
        'cluster': cluster_address(address, blockchain, txs) if args.cluster else {},
        'tags': get_address_tags(address, blockchain),
        'risk_score': assess_risk(address, blockchain, balance, txs),
    }
    return findings


def analyze_transaction(tx_hash: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze transaction (fetches once and derives details)."""
    requested_chain = getattr(args, 'blockchain', 'all')
    blockchain = detect_blockchain_from_tx(tx_hash) if requested_chain == 'all' else requested_chain
    raw_tx = _fetch_tx_raw(tx_hash, blockchain)
    findings = {
        'tx_hash': tx_hash,
        'blockchain': blockchain,
        'status': get_tx_status(tx_hash, raw_tx),
        'details': get_tx_details(tx_hash, raw_tx),
        'inputs': get_tx_inputs(tx_hash, raw_tx),
        'outputs': get_tx_outputs(tx_hash, raw_tx),
        'fee': get_tx_fee(tx_hash, raw_tx),
        'value': get_tx_value(tx_hash, raw_tx),
        'graph': build_tx_graph(tx_hash, args.depth, raw_tx) if args.depth > 0 else {},
    }
    return findings


def analyze_entity(entity: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze entity (exchange, service, etc.)."""
    findings = {
        'entity': entity,
        'known_addresses': get_entity_addresses(entity),
        'labels': get_entity_labels(entity),
        'volume_estimate': estimate_volume(entity),
        'risk_assessment': assess_entity_risk(entity),
    }
    return findings


# --- Validation & detection helpers ---

def _verify_base58check(address: str) -> bool:
    """Verify Base58Check encoding and 4-byte double-SHA256 checksum."""
    if not address or any(c not in _BASE58_MAP for c in address):
        return False
    num = 0
    for c in address:
        num = num * 58 + _BASE58_MAP[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    leading_zeros = len(address) - len(address.lstrip('1'))
    decoded = b'\x00' * leading_zeros + raw
    if len(decoded) < 5:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


def detect_blockchain(address: str) -> str:
    """Detect blockchain from address format."""
    addr = (address or "").strip()
    if addr.startswith(('1', '3', 'bc1')):
        return 'btc'
    if addr.startswith(('0x', '0X')):
        return 'eth'
    if addr.startswith('T') and len(addr) == 34:
        return 'trx'
    if addr.startswith(('L', 'M', 'ltc1')):
        return 'ltc'
    if addr.startswith('D') and len(addr) == 34:
        return 'doge'
    if addr.startswith('bnb1'):
        return 'bsc'
    return 'unknown'


def detect_blockchain_from_tx(tx_hash: str) -> str:
    """Detect blockchain from transaction hash."""
    h = (tx_hash or "").strip()
    if h.startswith(('0x', '0X')) and len(h) == 66 and _HEX64_RE.match(h[2:]):
        return 'eth'
    if len(h) == 64 and _HEX64_RE.match(h):
        return 'btc'
    return 'unknown'


def validate_address(address: str, blockchain: str) -> bool:
    """Validate address format and checksum for supported blockchains."""
    print(f"  {Colors.YELLOW}[~] Validating address...{Colors.RESET}")
    addr = (address or "").strip()
    if not addr:
        return False
    chain = (blockchain or "").lower()
    if chain == 'btc':
        if addr.lower().startswith('bc1'):
            return bool(_BECH32_RE.match(addr.lower()))
        return 26 <= len(addr) <= 35 and addr[0] in ('1', '3') and _verify_base58check(addr)
    if chain in ('eth', 'bsc'):
        if chain == 'bsc' and addr.lower().startswith('bnb1'):
            return bool(_BECH32_RE.match(addr.lower()))
        return bool(_ETH_ADDR_RE.match(addr))
    if chain == 'trx':
        return len(addr) == 34 and addr.startswith('T') and _verify_base58check(addr)
    if chain == 'ltc':
        if addr.lower().startswith('ltc1'):
            return bool(_BECH32_RE.match(addr.lower()))
        return 26 <= len(addr) <= 35 and addr[0] in ('L', 'M') and _verify_base58check(addr)
    if chain == 'doge':
        return len(addr) == 34 and addr.startswith('D') and _verify_base58check(addr)
    return False


# --- Blockchain API queries ---

def get_balance(address: str, blockchain: str) -> Dict[str, Any]:
    """Get address balance from public blockchain explorers."""
    print(f"  {Colors.YELLOW}[~] Fetching balance...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        return {'error': 'requests not installed'}

    chain = (blockchain or "").lower()
    try:
        if chain == 'btc':
            resp = requests.get(f"https://blockstream.info/api/address/{address}",
                                headers=_HEADERS, timeout=15)
            if resp.status_code != 200:
                return {'error': f'HTTP {resp.status_code}'}
            data = resp.json()
            c = data.get('chain_stats', {})
            m = data.get('mempool_stats', {})
            funded = c.get('funded_txo_sum', 0)
            spent = c.get('spent_txo_sum', 0)
            mem_bal = m.get('funded_txo_sum', 0) - m.get('spent_txo_sum', 0)
            return {
                'unit': 'BTC',
                'confirmed': f"{(funded - spent) / 1e8:.8f}",
                'unconfirmed': f"{mem_bal / 1e8:.8f}",
                'total_received': f"{funded / 1e8:.8f}",
                'total_sent': f"{spent / 1e8:.8f}",
                'tx_count': c.get('tx_count', 0) + m.get('tx_count', 0),
                'source': 'blockstream.info',
            }

        if chain == 'eth':
            api_key = os.environ.get('ETHERSCAN_API_KEY', '')
            if api_key:
                resp = requests.get(
                    "https://api.etherscan.io/api",
                    params={'module': 'account', 'action': 'balance',
                            'address': address, 'tag': 'latest', 'apikey': api_key},
                    headers=_HEADERS, timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == '1':
                        wei = int(data['result'])
                        return {
                            'unit': 'ETH',
                            'confirmed': f"{wei / 1e18:.8f}",
                            'source': 'etherscan.io',
                        }
            token = os.environ.get('BLOCKCYPHER_TOKEN', '')
            params = {'token': token} if token else {}
            resp = requests.get(
                f"https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance",
                params=params, headers=_HEADERS, timeout=15,
            )
            if resp.status_code != 200:
                return {'error': f'HTTP {resp.status_code}'}
            d = resp.json()
            return {
                'unit': 'ETH',
                'confirmed': f"{d.get('balance', 0) / 1e18:.8f}",
                'unconfirmed': f"{d.get('unconfirmed_balance', 0) / 1e18:.8f}",
                'total_received': f"{d.get('total_received', 0) / 1e18:.8f}",
                'total_sent': f"{d.get('total_sent', 0) / 1e18:.8f}",
                'tx_count': d.get('n_tx', 0),
                'source': 'blockcypher.com',
            }

        if chain in ('ltc', 'doge'):
            token = os.environ.get('BLOCKCYPHER_TOKEN', '')
            params = {'token': token} if token else {}
            resp = requests.get(
                f"https://api.blockcypher.com/v1/{chain}/main/addrs/{address}/balance",
                params=params, headers=_HEADERS, timeout=15,
            )
            if resp.status_code != 200:
                return {'error': f'HTTP {resp.status_code}'}
            d = resp.json()
            return {
                'unit': chain.upper(),
                'confirmed': f"{d.get('balance', 0) / 1e8:.8f}",
                'unconfirmed': f"{d.get('unconfirmed_balance', 0) / 1e8:.8f}",
                'total_received': f"{d.get('total_received', 0) / 1e8:.8f}",
                'total_sent': f"{d.get('total_sent', 0) / 1e8:.8f}",
                'tx_count': d.get('n_tx', 0),
                'source': 'blockcypher.com',
            }

        return {'error': f'Public balance API not configured for {chain}'}
    except Exception as e:
        return {'error': str(e)}


def get_transactions(address: str, blockchain: str, depth: int) -> List[Dict[str, Any]]:
    """Get recent transaction history for an address."""
    print(f"  {Colors.YELLOW}[~] Fetching transactions (depth: {depth})...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        return []

    limit = max(1, min(25, depth * 5))
    chain = (blockchain or "").lower()
    try:
        if chain == 'btc':
            resp = requests.get(f"https://blockstream.info/api/address/{address}/txs",
                                headers=_HEADERS, timeout=15)
            if resp.status_code != 200:
                return []
            txs = resp.json()[:limit]
            out = []
            for tx in txs:
                inputs = [
                    vin.get('prevout', {}).get('scriptpubkey_address')
                    for vin in tx.get('vin', [])
                    if vin.get('prevout', {}).get('scriptpubkey_address')
                ]
                outputs = [
                    {
                        'address': vout.get('scriptpubkey_address'),
                        'value_btc': round(vout.get('value', 0) / 1e8, 8),
                    }
                    for vout in tx.get('vout', [])
                ]
                out.append({
                    'txid': tx.get('txid'),
                    'confirmed': tx.get('status', {}).get('confirmed', False),
                    'block_height': tx.get('status', {}).get('block_height'),
                    'fee_btc': round(tx.get('fee', 0) / 1e8, 8),
                    'input_addresses': inputs,
                    'outputs': outputs,
                })
            return out
    except Exception:
        return []
    return []


def cluster_address(address: str, blockchain: str,
                    txs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Perform common-input-ownership clustering from observed transactions."""
    print(f"  {Colors.YELLOW}[~] Performing address clustering...{Colors.RESET}")
    related = {address}
    for tx in (txs or []):
        in_addrs = tx.get('input_addresses') or []
        if address in in_addrs:
            related.update(a for a in in_addrs if a)
    return {
        'addresses': sorted(related),
        'size': len(related),
        'heuristics': ['common_input_ownership'],
    }


def get_address_tags(address: str, blockchain: str) -> List[Dict[str, str]]:
    """Return known attribution tags (requires external threat-intel feed)."""
    print(f"  {Colors.YELLOW}[~] Checking address tags...{Colors.RESET}")
    return []


def assess_risk(address: str, blockchain: str,
                balance: Optional[Dict[str, Any]] = None,
                txs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Basic heuristic risk summary based on real on-chain activity."""
    print(f"  {Colors.YELLOW}[~] Assessing risk...{Colors.RESET}")
    factors: List[str] = []
    score = 0
    tx_count = (balance or {}).get('tx_count', 0) if isinstance(balance, dict) else 0
    if isinstance(tx_count, int) and tx_count > 1000:
        factors.append('high_transaction_volume')
        score += 20
    if txs and any(len(t.get('input_addresses', [])) > 10 for t in txs):
        factors.append('multi_input_consolidation_or_coinjoin')
        score += 15
    level = 'low' if score < 30 else ('medium' if score < 60 else 'high')
    return {
        'score': score,
        'level': level,
        'factors': factors,
        'note': 'On-chain heuristics only; sanctions/mixer feeds require a commercial API.',
    }


def _fetch_tx_raw(tx_hash: str, blockchain: str) -> Dict[str, Any]:
    """Fetch raw transaction JSON from Blockstream (BTC)."""
    try:
        import requests
    except ImportError:
        return {'error': 'requests not installed'}

    if (blockchain or "").lower() == 'btc':
        try:
            resp = requests.get(f"https://blockstream.info/api/tx/{tx_hash}",
                                headers=_HEADERS, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            return {'error': f'HTTP {resp.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    return {'error': f'Public TX explorer not configured for {blockchain}'}


def get_tx_status(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> str:
    """Get transaction confirmation status."""
    print(f"  {Colors.YELLOW}[~] Checking transaction status...{Colors.RESET}")
    if not raw_tx or raw_tx.get('error'):
        return 'unknown'
    return 'confirmed' if raw_tx.get('status', {}).get('confirmed') else 'unconfirmed'


def get_tx_details(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get transaction metadata."""
    print(f"  {Colors.YELLOW}[~] Fetching transaction details...{Colors.RESET}")
    if not raw_tx or raw_tx.get('error'):
        return {'error': (raw_tx or {}).get('error', 'unavailable')}
    st = raw_tx.get('status', {})
    return {
        'block': st.get('block_height'),
        'block_hash': st.get('block_hash'),
        'block_time': st.get('block_time'),
        'size': raw_tx.get('size'),
        'weight': raw_tx.get('weight'),
        'version': raw_tx.get('version'),
    }


def get_tx_inputs(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Get transaction inputs."""
    if not raw_tx or raw_tx.get('error'):
        return []
    return [
        {
            'address': vin.get('prevout', {}).get('scriptpubkey_address'),
            'value_btc': round(vin.get('prevout', {}).get('value', 0) / 1e8, 8),
        }
        for vin in raw_tx.get('vin', [])
    ]


def get_tx_outputs(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Get transaction outputs."""
    if not raw_tx or raw_tx.get('error'):
        return []
    return [
        {
            'address': vout.get('scriptpubkey_address'),
            'value_btc': round(vout.get('value', 0) / 1e8, 8),
        }
        for vout in raw_tx.get('vout', [])
    ]


def get_tx_fee(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> str:
    """Get transaction fee."""
    if not raw_tx or raw_tx.get('error') or raw_tx.get('fee') is None:
        return 'unknown'
    return f"{raw_tx['fee'] / 1e8:.8f} BTC"


def get_tx_value(tx_hash: str, raw_tx: Optional[Dict[str, Any]] = None) -> str:
    """Get total transaction output value."""
    if not raw_tx or raw_tx.get('error'):
        return 'unknown'
    total = sum(vout.get('value', 0) for vout in raw_tx.get('vout', []))
    return f"{total / 1e8:.8f} BTC"


def build_tx_graph(tx_hash: str, depth: int,
                   raw_tx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build input -> tx -> output graph from real TX data."""
    print(f"  {Colors.YELLOW}[~] Building transaction graph (depth: {depth})...{Colors.RESET}")
    if not raw_tx or raw_tx.get('error'):
        return {'nodes': [], 'edges': []}
    nodes = [{'id': tx_hash, 'type': 'tx'}]
    edges = []
    seen = {tx_hash}
    for vin in raw_tx.get('vin', []):
        addr = vin.get('prevout', {}).get('scriptpubkey_address')
        if addr:
            if addr not in seen:
                seen.add(addr)
                nodes.append({'id': addr, 'type': 'address'})
            edges.append({'from': addr, 'to': tx_hash,
                          'value_btc': round(vin.get('prevout', {}).get('value', 0) / 1e8, 8)})
    for vout in raw_tx.get('vout', []):
        addr = vout.get('scriptpubkey_address')
        if addr:
            if addr not in seen:
                seen.add(addr)
                nodes.append({'id': addr, 'type': 'address'})
            edges.append({'from': tx_hash, 'to': addr,
                          'value_btc': round(vout.get('value', 0) / 1e8, 8)})
    return {'nodes': nodes, 'edges': edges}


def get_entity_addresses(entity: str) -> List[Dict[str, Any]]:
    """Entity address lookup requires an external attribution database."""
    print(f"  {Colors.YELLOW}[~] Fetching entity addresses...{Colors.RESET}")
    return []


def get_entity_labels(entity: str) -> List[str]:
    """Return known labels (none without an external attribution feed)."""
    return []


def estimate_volume(entity: str) -> Dict[str, Any]:
    """Volume estimation requires an external analytics feed."""
    return {'status': 'unavailable', 'note': 'Requires external blockchain analytics API'}


def assess_entity_risk(entity: str) -> Dict[str, Any]:
    """Entity risk assessment requires an external compliance feed."""
    return {'status': 'unavailable', 'note': 'Requires external compliance/sanctions API'}


def output_results(results: Dict[str, Any], args: argparse.Namespace):
    """Output results in specified format."""
    _output_results(results, args, mode="target")


def format_results_txt(results: Dict[str, Any]) -> str:
    """Format results as text."""
    return _format_results_txt(results, mode="target")


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    return _format_results_csv(results, mode="target")


def format_dict(d: Dict, indent: int = 0) -> str:
    """Format dictionary as indented text."""
    return _format_dict(d, indent=indent)


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    return _flatten_dict(d, parent_key=parent_key, sep=sep)
