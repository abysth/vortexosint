"""Tests for vortexosint.modules.crypto_module."""

from vortexosint.modules import crypto_module


def test_detect_blockchain():
    assert crypto_module.detect_blockchain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"
    assert crypto_module.detect_blockchain("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == "btc"
    assert crypto_module.detect_blockchain("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0") == "eth"
    assert crypto_module.detect_blockchain("unknown-addr") == "unknown"


def test_validate_address_checksum_and_format():
    # Satoshi's genesis address (valid Base58Check)
    assert crypto_module.validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc") is True
    # Corrupted last char -> invalid checksum
    assert crypto_module.validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "btc") is False
    # Valid Bech32 BTC
    assert crypto_module.validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "btc") is True
    # Valid ETH
    assert crypto_module.validate_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0", "eth") is True
    # Too short ETH
    assert crypto_module.validate_address("0x1234", "eth") is False


def test_get_balance_btc_mocked(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "chain_stats": {"funded_txo_sum": 150000000, "spent_txo_sum": 50000000, "tx_count": 3},
                "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 0},
            }

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    bal = crypto_module.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc")
    assert bal["unit"] == "BTC"
    assert bal["confirmed"] == "1.00000000"
    assert bal["tx_count"] == 3


def test_cluster_address_common_input():
    txs = [
        {"input_addresses": ["addrA", "addrB"]},
        {"input_addresses": ["addrC"]},
    ]
    res = crypto_module.cluster_address("addrA", "btc", txs)
    assert res["addresses"] == ["addrA", "addrB"]
    assert res["size"] == 2
